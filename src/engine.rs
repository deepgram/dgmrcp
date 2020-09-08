use crate::{channel::Channel, error::Error, ffi, helper::*, pool::Pool};
use serde::Deserialize;
use std::{ffi::CStr, mem, sync::Arc};

static RECOG_ENGINE_TASK_NAME: &[u8] = b"DG ASR Engine\0";

/// Define the engine v-table
pub static ENGINE_VTABLE: ffi::mrcp_engine_method_vtable_t = ffi::mrcp_engine_method_vtable_t {
    destroy: Some(engine_destroy),
    open: Some(engine_open),
    close: Some(engine_close),
    create_channel: Some(engine_create_channel),
};

unsafe extern "C" fn engine_destroy(_engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    ffi::TRUE
}

unsafe extern "C" fn engine_open(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    info!("engine open");

    let mut pool = Pool::from((*engine).pool);

    let config = ffi::mrcp_engine_config_get(engine);
    let config: Config = match crate::config::from_apr_table((*config).params) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to parse config: {:?}", err);
            mrcp_engine_open_respond(engine, ffi::FALSE);
            return ffi::FALSE;
        }
    };
    let config = Arc::new(config);
    debug!("Parsed engine configuration");

    let task_data = match TaskData::new() {
        Ok(data) => data,
        Err(err) => {
            error!("failed to spawn task: {}", err);
            return ffi::FALSE;
        }
    };
    let runtime_handle = task_data.runtime_handle.clone();
    let task_data = pool.palloc(task_data);

    let msg_pool = ffi::apt_task_msg_pool_create_dynamic(
        mem::size_of::<crate::channel::Message>(),
        pool.get(),
    );
    let consumer_task = ffi::apt_consumer_task_create(task_data as *mut _, msg_pool, pool.get());
    if consumer_task.is_null() {
        return ffi::FALSE;
    }
    let task = ffi::apt_consumer_task_base_get(consumer_task);
    let c_str = CStr::from_bytes_with_nul_unchecked(RECOG_ENGINE_TASK_NAME);
    ffi::apt_task_name_set(task, c_str.as_ptr());
    let vtable = {
        let ptr = ffi::apt_task_vtable_get(task);
        if ptr.is_null() {
            return ffi::FALSE;
        }
        &mut *ptr
    };
    vtable.destroy = Some(task_destroy);
    vtable.process_msg = Some(task_process_msg);
    ffi::apt_task_start(task);

    (*engine).obj = Box::into_raw(Box::new(Engine {
        task: consumer_task,
        runtime_handle,
        config,
    })) as *mut _;

    info!("Opened engine");
    mrcp_engine_open_respond(engine, ffi::TRUE)
}

unsafe extern "C" fn engine_close(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    debug!("Closing the Deepgram ASR Engine");
    {
        let engine = Box::from_raw((*engine).obj as *mut Engine);
        let task = ffi::apt_consumer_task_base_get(engine.task);
        ffi::apt_task_terminate(task, ffi::TRUE);
        ffi::apt_task_destroy(task);
    }
    (*engine).obj = std::ptr::null_mut();
    mrcp_engine_close_respond(engine)
}

unsafe extern "C" fn engine_create_channel(
    engine: *mut ffi::mrcp_engine_t,
    pool: *mut ffi::apr_pool_t,
) -> *mut ffi::mrcp_engine_channel_t {
    Channel::alloc(engine, &mut pool.into())
        .expect("Failed to allocate the Deepgram MRCP engine channel.")
        .as_ptr()
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub brain_url: url::Url,
    pub brain_username: String,
    pub brain_password: String,
    #[serde(default = "Config::default_chunk_size")]
    pub chunk_size: u64,
    #[serde(default)]
    pub stream_results: bool,
    #[serde(default)]
    pub plaintext_results: bool,
    pub language: Option<String>,
}

impl Config {
    /// 0.25 seconds of 8kHz 16-bit audio.
    ///
    /// UniMRCP sends audio to the server plugin in chunks of 160
    /// bytes, which would incur an unreasonable amount of messaging
    /// overhead.
    const fn default_chunk_size() -> u64 {
        4000
    }
}

/// The Deepgram ASR engine.
#[repr(C)]
pub struct Engine {
    pub task: *mut ffi::apt_consumer_task_t,

    pub runtime_handle: tokio::runtime::Handle,

    pub config: Arc<Config>,
}

struct TaskData {
    thread_handle: std::thread::JoinHandle<()>,
    runtime_handle: tokio::runtime::Handle,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TaskData {
    fn new() -> Result<Self, Error> {
        debug!("TaskData::new {:?}", std::thread::current());

        let mut runtime = tokio::runtime::Runtime::new().map_err(|_| Error::Initialization)?;
        let runtime_handle = runtime.handle().clone();

        let (shutdown, rx) = tokio::sync::oneshot::channel();
        let thread_handle = std::thread::Builder::new()
            .name("DG Scheduler".to_string())
            .spawn(|| {
                info!("starting tokio runtime");
                runtime.block_on(async {
                    info!("started tokio runtime");
                    rx.await.ok();
                });
                info!("dropping tokio runtime");
                drop(runtime);
                info!("dropped tokio runtime");
            })
            .map_err(|_| Error::Initialization)?;

        Ok(TaskData {
            thread_handle,
            runtime_handle,
            shutdown,
        })
    }
}

/// Destroy the task data.
///
/// # Safety
///
/// Note that this leaves the task data in an uninitialized state.
unsafe extern "C" fn task_destroy(task: *mut ffi::apt_task_t) -> ffi::apt_bool_t {
    info!("task destroy");

    let consumer_task = ffi::apt_task_object_get(task) as *mut ffi::apt_consumer_task_t;
    let data = ffi::apt_consumer_task_object_get(consumer_task) as *mut TaskData;

    let TaskData {
        thread_handle,
        shutdown,
        ..
    } = std::ptr::read(data);

    shutdown.send(()).ok();
    info!("joining scheduler thread");
    thread_handle.join().ok();
    info!("joined scheduler thread");

    ffi::TRUE
}

/// Process a message. This gets invoked by the UniMRCP runtime. Note
/// that `msg` is valid when this function is called, but it is
/// deallocated immediately after this function is returns. Therefore,
/// this function needs call the associated `Message` object's `drop`
/// function.
unsafe extern "C" fn task_process_msg(
    _task: *mut ffi::apt_task_t,
    msg: *mut ffi::apt_task_msg_t,
) -> ffi::apt_bool_t {
    debug!("Message processing...");

    // Move the contents pointed to by the `Message` pointer onto the
    // stack. The stack allocated `Message` will be dropped by this
    // Rust plugin, and the heap memory owned by the `apt_task_msg_t`
    // will be freed by the UniMRCP runtime after this function
    // returns.
    let msg = std::ptr::read(&(*msg).data as *const _ as *const crate::channel::Message);

    let channel = &mut *(msg.channel.as_ref().method_obj as *mut Channel);
    channel.process_message(msg);

    ffi::TRUE
}

/// Log in to the Brain service, returning an HTTP client
/// preconfigured with JWT auth credentials.
async fn login(config: Arc<Config>) -> Result<reqwest::Client, Error> {
    let client = reqwest::Client::builder().cookie_store(true).build()?;

    let base_url = reqwest::Url::parse(config.brain_url.as_str())?;

    #[derive(Debug, Deserialize)]
    struct Response {
        token: String,
        auth: bool,
    }

    let endpoint = base_url.join("/v2/login")?;
    let response: Response = client
        .post(endpoint)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    trace!("Got XSRF token: {}", response.token);

    let endpoint = base_url.join("/v2/login")?;
    let response: Response = client
        .post(endpoint)
        .header("x-xsrf-token", response.token)
        .basic_auth(
            config.brain_username.as_str(),
            Some(config.brain_password.as_str()),
        )
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    trace!("received auth: {:?}", response);

    if !response.auth {
        return Err(Error::Initialization);
    }

    Ok(client)
}
