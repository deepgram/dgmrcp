use crate::{channel::Channel, error::Error, ffi, helper::*, message::*, pool::Pool};
use std::ffi::CStr;
use std::mem;

static RECOG_ENGINE_TASK_NAME: &[u8] = b"Deepgram ASR Engine\0";

/// Define the engine v-table
pub static ENGINE_VTABLE: ffi::mrcp_engine_method_vtable_t = ffi::mrcp_engine_method_vtable_t {
    destroy: Some(engine_destroy),
    open: Some(engine_open),
    close: Some(engine_close),
    create_channel: Some(engine_create_channel),
};

unsafe extern "C" fn engine_destroy(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    Engine::map(engine, |engine| engine.destroy());
    ffi::TRUE
}

unsafe extern "C" fn engine_open(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    Engine::map(engine, |engine| engine.open());
    mrcp_engine_open_respond(engine, ffi::TRUE)
}

unsafe extern "C" fn engine_close(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    Engine::map(engine, |engine| engine.close());
    mrcp_engine_close_respond(engine)
}

unsafe extern "C" fn engine_create_channel(
    engine: *mut ffi::mrcp_engine_t,
    pool: *mut ffi::apr_pool_t,
) -> *mut ffi::mrcp_engine_channel_t {
    let channel = Box::into_raw(
        Channel::alloc(engine, &mut pool.into())
            .expect("Failed to allocate the Deepgram MRCP engine channel."),
    );
    (*channel).channel.unwrap()
}

/// The Deepgram ASR engine.
#[repr(C)]
pub struct Engine {
    pub task: Option<*mut ffi::apt_consumer_task_t>,
}

impl Engine {
    pub(crate) fn alloc(pool: &mut Pool) -> Result<Box<Engine>, Error> {
        info!("Constructing the Deepgram ASR Engine.");
        let src = Self { task: None };
        let ptr: *mut Self =
            unsafe { ffi::apr_palloc(pool.get(), mem::size_of::<Self>()) as *mut _ };
        unsafe { ptr.copy_from_nonoverlapping(&src as *const _, 1) };

        mem::forget(src);

        let msg_pool =
            unsafe { ffi::apt_task_msg_pool_create_dynamic(mem::size_of::<Message>(), pool.get()) };
        let task = unsafe { ffi::apt_consumer_task_create(ptr as *mut _, msg_pool, pool.get()) };
        if task.is_null() {
            return Err(Error::Initialization);
        }

        unsafe { (*ptr).task = Some(task) };

        let task = unsafe { ffi::apt_consumer_task_base_get(task) };
        let c_str = unsafe { CStr::from_bytes_with_nul_unchecked(RECOG_ENGINE_TASK_NAME) };
        unsafe { ffi::apt_task_name_set(task, c_str.as_ptr()) };
        let vtable = unsafe { ffi::apt_task_vtable_get(task) };
        if !vtable.is_null() {
            unsafe {
                (*vtable).process_msg = Some(msg_process);
            }
        }

        Ok(unsafe { Box::from_raw(ptr) })
    }

    pub(crate) fn map<F, T>(ptr: *mut ffi::mrcp_engine_t, func: F) -> T
    where
        F: FnOnce(&mut Engine) -> T,
    {
        let mut engine: Box<Engine> = unsafe { Box::from_raw((*ptr).obj as *mut _) };
        let r = func(&mut *engine);
        Box::into_raw(engine);
        r
    }

    fn destroy(&mut self) {
        debug!("Destroying the Deepgram ASR engine.");
        if let Some(task) = self.task.take() {
            let task = unsafe { ffi::apt_consumer_task_base_get(task) };
            unsafe {
                ffi::apt_task_destroy(task);
            }
        }
    }

    fn open(&mut self) {
        debug!("Opening the Deepgram ASR Engine.");
        if let Some(task) = self.task {
            let task = unsafe { ffi::apt_consumer_task_base_get(task) };
            unsafe {
                ffi::apt_task_start(task);
            }
        }
    }

    fn close(&mut self) {
        debug!("Closing the Deepgram ASR Engine.");
        if let Some(task) = self.task {
            let task = unsafe { ffi::apt_consumer_task_base_get(task) };
            unsafe {
                ffi::apt_task_terminate(task, ffi::TRUE);
            }
        }
    }
}

unsafe extern "C" fn msg_process(
    _task: *mut ffi::apt_task_t,
    msg: *mut ffi::apt_task_msg_t,
) -> ffi::apt_bool_t {
    debug!("Message processing...");

    // Encapsulate the message payload.
    #[allow(clippy::cast_ptr_alignment)]
    let msg = Box::from_raw(&mut (*msg).data as *mut _ as *mut Message);

    match msg.message_type {
        MessageType::Open => {
            mrcp_engine_channel_open_respond(msg.channel, ffi::TRUE);
        }
        MessageType::Close => {
            let channel = Box::from_raw((*(*msg).channel).method_obj as *mut Channel);
            mrcp_engine_channel_close_respond(msg.channel);
            Box::into_raw(channel);
        }
        MessageType::RequestProcess => {
            dispatch_request(msg.channel, msg.request);
        }
    }
    Box::into_raw(msg);
    ffi::TRUE
}
