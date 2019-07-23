use crate::{channel::Channel, helper::*, debug, ffi, info, warn, pool::Pool, error::Error, request::Request, stream::*};
use std::ptr;
use std::mem::{self, ManuallyDrop};
use std::ffi::{CStr, CString};

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
    unsafe { mrcp_engine_open_respond(engine, ffi::TRUE) }
}

unsafe extern "C" fn engine_close(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    Engine::map(engine, |engine| engine.close());
    unsafe { mrcp_engine_close_respond(engine) }
}

unsafe extern "C" fn engine_create_channel(
    engine: *mut ffi::mrcp_engine_t,
    pool: *mut ffi::apr_pool_t,
) -> *mut ffi::mrcp_engine_channel_t {
    unsafe {
        let channel = Box::into_raw(
            Channel2::alloc(engine, &mut pool.into()).expect("Failed to allocate the Deepgram MRCP engine channel.")
        );
        (*channel).channel.unwrap()
    }
}

/// The Deepgram ASR engine.
#[repr(C)]
pub struct Engine {
    task: Option<*mut ffi::apt_consumer_task_t>,
}

impl Engine {
    pub fn alloc(pool: &mut Pool) -> Result<Box<Engine>, Error> {
        info!("Constructing the Deepgram ASR Engine.");
        let src = Self {
            task: None,
        };
        let ptr: *mut Self = unsafe {
            ffi::apr_palloc(pool.get(), mem::size_of::<Self>()) as *mut _
        };
        unsafe { ptr.copy_from_nonoverlapping(&src as *const _, 1) };

        mem::forget(src);

        let msg_pool = unsafe { ffi::apt_task_msg_pool_create_dynamic(mem::size_of::<Message>(), pool.get()) };
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
            unsafe { (*vtable).process_msg = Some(msg_process); }
        }

        Ok(
            unsafe { Box::from_raw(ptr) }
        )
    }

    pub fn map<F, T>(ptr: *mut ffi::mrcp_engine_t, func: F) -> T
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
            unsafe { ffi::apt_task_destroy(task); }
        }
    }

    fn open(&mut self) {
        debug!("Opening the Deepgram ASR Engine.");
        if let Some(task) = self.task {
            let task = unsafe { ffi::apt_consumer_task_base_get(task) };
            unsafe { ffi::apt_task_start(task); }
        }
    }

    fn close(&mut self) {
        debug!("Closing the Deepgram ASR Engine.");
        if let Some(task) = self.task {
            let task = unsafe { ffi::apt_consumer_task_base_get(task) };
            unsafe { ffi::apt_task_terminate(task, ffi::TRUE); }
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum MessageType {
    Open,
    Close,
    RequestProcess,
}

struct Message {
    message_type: MessageType,
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
}

#[repr(C)]
pub struct Channel2 {
    pub demo_engine: Option<*mut Engine>,
    pub channel: Option<*mut ffi::mrcp_engine_channel_t>,
    pub recog_request: Option<*mut ffi::mrcp_message_t>,
    pub stop_response: Option<*mut ffi::mrcp_message_t>,
    pub timers_started: ffi::apt_bool_t,
    pub detector: Option<*mut ffi::mpf_activity_detector_t>,
}

impl Channel2 {
    pub fn alloc(engine: *mut ffi::mrcp_engine_t, pool: &mut Pool) -> Result<Box<Channel2>, Error> {
        info!("Constructing a Deepgram ASR Engine Channel.");
        let src = Self {
            demo_engine: Some(unsafe { (*engine).obj as *mut _ }),
            recog_request: None,
            stop_response: None,
            detector: Some(unsafe { ffi::mpf_activity_detector_create(pool.get()) }),
            timers_started: ffi::FALSE as i32,
            channel: None,
        };
        let ptr: *mut Self = unsafe {
            ffi::apr_palloc(pool.get(), mem::size_of::<Self>()) as *mut _
        };
        unsafe { ptr.copy_from_nonoverlapping(&src as *const _, 1) };
        mem::forget(src);

        let caps = unsafe { mpf_sink_stream_capabilities_create(pool.get()) };
        let codec: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"LPCM\0") };
        unsafe {
            mpf_codec_capabilities_add(
                &mut (*caps).codecs as *mut _,
                (ffi::mpf_sample_rates_e::MPF_SAMPLE_RATE_8000 | ffi::mpf_sample_rates_e::MPF_SAMPLE_RATE_16000) as i32,
                codec.as_ptr(),
            );
        }

        let termination = unsafe {
            ffi::mrcp_engine_audio_termination_create(
                ptr as *mut _,
                &STREAM_VTABLE,
                caps,
                pool.get()
            )
        };

        unsafe {
            (*ptr).channel = Some(ffi::mrcp_engine_channel_create(
                engine,
                &CHANNEL_VTABLE,
                ptr as *mut _,
                termination,
                pool.get()
            ));
        }

        Ok(
            unsafe { Box::from_raw(ptr) }
        )
    }

    pub fn start_of_input(&mut self) -> bool {
        debug!("Start-of-input.");
        let message = unsafe {
            ffi::mrcp_event_create(
                self.recog_request.unwrap() as *const _,
                ffi::mrcp_recognizer_event_id::RECOGNIZER_START_OF_INPUT as usize,
                (*self.recog_request.unwrap()).pool,
            )
        };

        if message.is_null() {
            false
        } else {
            unsafe {
                (*message).start_line.request_state = ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
                mrcp_engine_channel_message_send(self.channel.unwrap(), message) != 0
            }
        }
    }

    pub fn recognition_complete(&mut self, cause: ffi::mrcp_recog_completion_cause_e::Type) -> bool {
        debug!("Recognition complete.");
        let message = unsafe {
            ffi::mrcp_event_create(
                self.recog_request.unwrap() as *const _,
                ffi::mrcp_recognizer_event_id::RECOGNIZER_RECOGNITION_COMPLETE as usize,
                (*self.recog_request.unwrap()).pool,
            )
        };

        if message.is_null() {
            return false;
        }

        let header = unsafe {
            mrcp_resource_header_prepare(message) as *mut ffi::mrcp_recog_header_t
        };
        if !header.is_null() {
            unsafe {
                (*header).completion_cause = cause;
                ffi::mrcp_resource_header_property_add(message, ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_COMPLETION_CAUSE as usize);
            }
        }

        unsafe {
            (*message).start_line.request_state = ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_COMPLETE;
        }

        if cause == ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS {
            //demo_recog_result_load
            unsafe {
                let body = CString::new(br#"<?xml version="1.0"?>
<result> 
  <interpretation grammar="session:request1@form-level.store" confidence="0.97">
    <instance>one</instance>
    <input mode="speech">one</input>
  </interpretation>
</result>
"#.to_vec()).unwrap();
                apt_string_assign_n(&mut (*message).body, body.as_ptr(), body.to_bytes().len(), (*message).pool);
            }

            let header = unsafe { mrcp_generic_header_prepare(message) };
            if !header.is_null() {
                unsafe {
                    let content_type = CStr::from_bytes_with_nul_unchecked(b"application/x-nlsml\0");
                    apt_string_assign(&mut (*header).content_type, content_type.as_ptr(), (*message).pool);
                    ffi::mrcp_generic_header_property_add(message, ffi::mrcp_generic_header_id::GENERIC_HEADER_CONTENT_TYPE as usize);
                }
            }
        }

        self.recog_request.take();

        unsafe {
            mrcp_engine_channel_message_send(self.channel.unwrap(), message) != 0
        }
    }
}

/// Define the engine v-table
static CHANNEL_VTABLE: ffi::mrcp_engine_channel_method_vtable_t = ffi::mrcp_engine_channel_method_vtable_t {
    destroy: Some(channel_destroy),
    open: Some(channel_open),
    close: Some(channel_close),
    process_request: Some(channel_process_request),
};

unsafe extern "C" fn channel_destroy(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    debug!("Destroying Deepgram ASR channel.");
    ffi::TRUE
}

unsafe extern "C" fn channel_open(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    debug!("Openinging Deepgram ASR channel.");
    demo_recog_msg_signal(MessageType::Open, channel, ptr::null_mut())
}

unsafe extern "C" fn channel_close(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    debug!("Closing Deepgram ASR channel.");
    demo_recog_msg_signal(MessageType::Close, channel, ptr::null_mut())
}

unsafe extern "C" fn channel_process_request(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    demo_recog_msg_signal(MessageType::RequestProcess, channel, request)
}

unsafe fn demo_recog_msg_signal(message_type: MessageType, channel: *mut ffi::mrcp_engine_channel_t, request: *mut ffi::mrcp_message_t) -> ffi::apt_bool_t {
    debug!("Message signal: {:?}", message_type);
    let demo_channel = Box::from_raw((*channel).method_obj as *mut Channel2);
    let demo_engine = demo_channel.demo_engine.unwrap();
    let task = ffi::apt_consumer_task_base_get((*demo_engine).task.unwrap());
    let msg = ffi::apt_task_msg_get(task);
    let r = if !msg.is_null() {
        (*msg).type_ = ffi::apt_task_msg_type_e::TASK_MSG_USER as i32;
        let mut demo_msg = Box::from_raw(&mut (*msg).data as *mut _ as *mut Message);
        demo_msg.message_type = message_type;
        demo_msg.channel = channel;
        demo_msg.request = request;
        Box::into_raw(demo_msg);
        ffi::apt_task_msg_signal(task, msg)
    } else {
        ffi::FALSE as i32
    };
    Box::into_raw(demo_channel);
    r
}

unsafe extern "C" fn msg_process(task: *mut ffi::apt_task_t, msg: *mut ffi::apt_task_msg_t) -> ffi::apt_bool_t {
    debug!("Message processing...");
    let demo_msg = Box::from_raw(&mut (*msg).data as *mut _ as *mut Message);
    match demo_msg.message_type {
        MessageType::Open => {
            mrcp_engine_channel_open_respond(demo_msg.channel, ffi::TRUE);
        }
        MessageType::Close => {
            let channel = Box::from_raw((*(*demo_msg).channel).method_obj as *mut Channel2);
            mrcp_engine_channel_close_respond(demo_msg.channel);
            Box::into_raw(channel);
        }
        MessageType::RequestProcess => {
            demo_recog_channel_request_dispatch(demo_msg.channel, demo_msg.request);
        }
    }
    Box::into_raw(demo_msg);
    ffi::TRUE
}

unsafe fn demo_recog_channel_recognize(channel: *mut ffi::mrcp_engine_channel_t, request: *mut ffi::mrcp_message_t, response: *mut ffi::mrcp_message_t) -> ffi::apt_bool_t {
    debug!("Channel recognize.");
    let mut recog_channel = ManuallyDrop::new(Box::from_raw((*channel).method_obj as *mut Channel2));
    let descriptor = ffi::mrcp_engine_sink_stream_codec_get(channel);

    if descriptor.is_null() {
        warn!("Failed to get codec description.");
        (*response).start_line.status_code = ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;
        return ffi::FALSE as i32;
    }

    recog_channel.timers_started = ffi::TRUE;

    let recog_header = mrcp_resource_header_get(request) as *mut ffi::mrcp_recog_header_t;
    if !recog_header.is_null() {
        if mrcp_resource_header_property_check(request, ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_START_INPUT_TIMERS as usize) == ffi::TRUE {
            recog_channel.timers_started = (*recog_header).start_input_timers;
        }
        if mrcp_resource_header_property_check(request, ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_NO_INPUT_TIMEOUT as usize) == ffi::TRUE {
            ffi::mpf_activity_detector_noinput_timeout_set(recog_channel.detector.unwrap(), (*recog_header).no_input_timeout);
        }
        if mrcp_resource_header_property_check(request, ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SPEECH_COMPLETE_TIMEOUT as usize) == ffi::TRUE {
            ffi::mpf_activity_detector_silence_timeout_set(recog_channel.detector.unwrap(), (*recog_header).speech_complete_timeout);
        }
    }

    (*response).start_line.request_state = ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
    mrcp_engine_channel_message_send(channel, response);
    recog_channel.recog_request = Some(request);
    ffi::TRUE
}

unsafe fn demo_recog_channel_request_dispatch(channel: *mut ffi::mrcp_engine_channel_t, request: *mut ffi::mrcp_message_t) -> ffi::apt_bool_t {
    debug!("Dispatching message.");
    let response = ffi::mrcp_response_create(request, (*request).pool);
    let processed = match ((*request).start_line).method_id as u32 {
        ffi::mrcp_recognizer_method_id::RECOGNIZER_RECOGNIZE => {
            demo_recog_channel_recognize(channel, request, response) != 0
        }
        ffi::mrcp_recognizer_method_id::RECOGNIZER_START_INPUT_TIMERS => {
            {
                let mut channel = ManuallyDrop::new(Box::from_raw((*channel).method_obj as *mut Channel2));
                channel.timers_started = ffi::TRUE;
            }
            mrcp_engine_channel_message_send(channel, response) != 0
        }
        ffi::mrcp_recognizer_method_id::RECOGNIZER_STOP => {
            let mut channel = ManuallyDrop::new(Box::from_raw((*channel).method_obj as *mut Channel2));
            channel.stop_response = Some(response);
            true
        }
        _ => false,
    };
    if !processed {
        mrcp_engine_channel_message_send(channel, response);
    }
    ffi::TRUE
}
