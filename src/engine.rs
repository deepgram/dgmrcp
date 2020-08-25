use crate::{channel::Channel, error::Error, ffi, helper::*, message::*, pool::Pool};
use serde::Deserialize;
use std::ffi::CStr;
use std::mem;

static RECOG_ENGINE_TASK_NAME: &[u8] = b"DG ASR Engine\0";

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
    let config = ffi::mrcp_engine_config_get(engine);

    let config: Config = match crate::config::from_apr_table((*config).params) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to parse config: {:?}", err);
            return mrcp_engine_open_respond(engine, ffi::FALSE as i32);
        }
    };
    debug!("Parsed engine configuration");

    let response = match Engine::map(engine, |engine| engine.open(config)) {
        Ok(()) => ffi::TRUE,
        Err(err) => {
            error!("{:?}", err);
            ffi::FALSE as i32
        }
    };
    mrcp_engine_open_respond(engine, response)
}

unsafe extern "C" fn engine_close(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    Engine::map(engine, |engine| engine.close());
    mrcp_engine_close_respond(engine)
}

unsafe extern "C" fn engine_create_channel(
    engine: *mut ffi::mrcp_engine_t,
    pool: *mut ffi::apr_pool_t,
) -> *mut ffi::mrcp_engine_channel_t {
    Channel::alloc(engine, &mut pool.into())
        .expect("Failed to allocate the Deepgram MRCP engine channel.")
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    brain_url: url::Url,
    brain_username: String,
    brain_password: String,
    #[serde(default = "Config::default_chunk_size")]
    pub chunk_size: u64,
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
    pub task: Option<*mut ffi::apt_consumer_task_t>,

    pub runtime_handle: Option<tokio::runtime::Handle>,

    // TODO: Not sure where config should live.
    pub config: Option<Config>,
}

impl Engine {
    pub(crate) fn alloc(pool: &mut Pool) -> Result<*mut Engine, Error> {
        info!("Constructing the Deepgram ASR Engine.");

        let src = Self {
            task: None,
            runtime_handle: None,
            config: None,
        };
        let ptr = pool.palloc(src);

        let task_data = TaskData::new(ptr)?;
        let runtime_handle = task_data.runtime_handle.clone();
        let task_data = pool.palloc(task_data);
        info!("task data ptr :: {:?}", task_data);

        let msg_pool =
            unsafe { ffi::apt_task_msg_pool_create_dynamic(mem::size_of::<Message>(), pool.get()) };
        let task =
            unsafe { ffi::apt_consumer_task_create(task_data as *mut _, msg_pool, pool.get()) };
        if task.is_null() {
            return Err(Error::Initialization);
        }

        unsafe { (*ptr).task = Some(task) };
        unsafe { (*ptr).runtime_handle = Some(runtime_handle) };

        let task = unsafe { ffi::apt_consumer_task_base_get(task) };
        let c_str = unsafe { CStr::from_bytes_with_nul_unchecked(RECOG_ENGINE_TASK_NAME) };
        unsafe { ffi::apt_task_name_set(task, c_str.as_ptr()) };
        let vtable = {
            let ptr = unsafe { ffi::apt_task_vtable_get(task) };
            if ptr.is_null() {
                return Err(Error::Initialization);
            }
            unsafe { &mut *ptr }
        };
        vtable.destroy = Some(task_destroy);
        vtable.process_msg = Some(task_process_msg);

        Ok(ptr)
    }

    pub(crate) fn map<F, T>(ptr: *mut ffi::mrcp_engine_t, func: F) -> T
    where
        F: FnOnce(&mut Engine) -> T,
    {
        let engine: &mut Engine = unsafe { &mut *((*ptr).obj as *mut _) };
        func(&mut *engine)
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

    fn open(&mut self, config: Config) -> Result<(), Error> {
        debug!("Opening the Deepgram ASR Engine.");

        // let mut headers = reqwest::header::HeaderMap::new();
        // headers.insert(
        //     reqwest::header::AUTHORIZATION,
        //     format!(
        //         "Basic {}",
        //         base64::encode(format!(
        //             "{}:{}",
        //             config.brain_username, config.brain_password
        //         ))
        //     )
        //     .parse()
        //     .unwrap(),
        // );
        // let client = reqwest::Client::builder()
        //     .default_headers(headers)
        //     .build()?;
        // let (tx, rx) = watch::channel(client);
        // self.client = Some(rx);

        // let cfg = config.clone();
        // self.runtime.as_mut().unwrap().spawn(async move {
        //     loop {
        //         info!("Refreshing login token");
        //         let duration = match login(cfg.clone()).await {
        //             Ok(client) => match tx.broadcast(client) {
        //                 Ok(()) => std::time::Duration::from_secs(30 * 60),
        //                 Err(_) => break,
        //             },
        //             Err(err) => {
        //                 error!("{}", err);
        //                 std::time::Duration::from_secs(1 * 60)
        //             }
        //         };

        //         tokio::time::delay_for(duration).await;
        //     }
        // });

        self.config = Some(config);

        if let Some(task) = self.task {
            let task = unsafe { ffi::apt_consumer_task_base_get(task) };
            unsafe {
                ffi::apt_task_start(task);
            }
        }

        Ok(())
    }

    fn close(&mut self) {
        debug!("Closing the Deepgram ASR Engine.");
        if let Some(task) = self.task {
            let task = unsafe { ffi::apt_consumer_task_base_get(task) };
            unsafe {
                ffi::apt_task_terminate(task, ffi::TRUE);
            }
        }

        // Drop config.
        self.config.take();
    }

    pub fn config(&self) -> &Config {
        self.config.as_ref().unwrap()
    }
}

struct TaskData {
    engine: *const Engine,
    thread_handle: std::thread::JoinHandle<()>,
    runtime_handle: tokio::runtime::Handle,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TaskData {
    fn new(engine: *const Engine) -> Result<Self, Error> {
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
            engine,
            thread_handle,
            runtime_handle,
            shutdown,
        })
    }

    /// Get a reference to the engine's config.
    fn config(&self) -> &Config {
        let engine = unsafe { &*self.engine };
        engine.config.as_ref().unwrap()
    }

    fn process_message(&self, msg: Message) {
        match msg.message_type {
            MessageType::Open {
                rx,
                sample_rate,
                channels,
            } => {
                let config = self.config();

                let auth = format!("{}:{}", config.brain_username, config.brain_password);

                let mut url = config.brain_url.join("listen/stream").unwrap();
                // TODO: Perhaps these should not be hardcoded?
                url.query_pairs_mut()
                    .append_pair("endpointing", "true")
                    .append_pair("interim_results", "true")
                    .append_pair("encoding", "linear16")
                    .append_pair("sample_rate", &sample_rate.to_string())
                    .append_pair("channels", &channels.to_string());

                info!("Building request to {}", url);

                let req = http::Request::builder()
                    .uri(url.as_str())
                    .header("Authorization", format!("Basic {}", base64::encode(auth)))
                    .body(())
                    .unwrap();

                // TODO: This feels wrong.
                #[derive(Clone, Copy)]
                struct SendPtr<T>(*mut T);
                unsafe impl<T> Send for SendPtr<T> {}

                let channel = SendPtr(msg.channel);

                self.runtime_handle.spawn(async move {
                    info!("Opening websocket connection");
                    let result = match tokio_tungstenite::connect_async(req).await {
                        Ok((socket, response)) => {
                            use futures::prelude::*;
                            info!("Opened websocket connection :: {:?}", response);

                            tokio::spawn(async move {
                                let (mut ws_tx, mut ws_rx) = socket.split();
                                let mut rx = rx;
                                let write = async {
                                    info!("Begin writing to websocket");

                                    while let Some(msg) = rx.next().await {
                                        if let Err(err) = ws_tx.send(msg).await {
                                            warn!("Websocket connection closed: {}", err);
                                        }
                                    }

                                    let end = tungstenite::Message::Binary(vec![]);
                                    if let Err(err) = ws_tx.send(end).await {
                                        warn!("Websocket connection closed: {}", err);
                                    }

                                    info!("Done writing to websocket");
                                };
                                let read = async move {
                                    while let Some(msg) = ws_rx.next().await {
                                        trace!("received ws msg: {:?}", msg);

                                        let msg = match msg {
                                            Ok(msg) => msg,
                                            Err(tungstenite::Error::ConnectionClosed) => break,
                                            Err(err) => {
                                                warn!("WebSocket error: {}", err);
                                                continue;
                                            }
                                        };

                                        #[derive(Deserialize)]
                                        #[serde(untagged)]
                                        enum Message {
                                            Results(crate::stem::StreamingResponse),
                                            Summary(crate::stem::Summary),
                                        }

                                        match msg {
                                            tungstenite::Message::Close(_) => {
                                                info!("Websocket is closing");
                                                break;
                                            }
                                            tungstenite::Message::Text(buf) => {
                                                let msg: Message =
                                                    match serde_json::from_str(&buf) {
                                                        Ok(msg) => msg,
                                                        Err(err) => {
                                                            warn!("Failed to deserialize streaming response: {}", err);
                                                            debug!("{}", buf);
                                                            continue;
                                                        }
                                                    };

                                                let channel = unsafe { &mut *((*channel.0).method_obj as *mut Channel) };
                                                match msg {
                                                    Message::Results(msg) => channel.results_available(msg),
                                                    Message::Summary(msg) => channel.results_summary(msg),
                                                }
                                            }
                                            _ => warn!("Unhandled WS message type"),
                                        }
                                    }
                                };

                                future::join(write, read).await;
                                drop(ws_tx);
                            });

                            true
                        }
                        Err(err) => {
                            error!("Failed to open websocket connection: {}", err);
                            false
                        }
                    };

                    unsafe {
                        mrcp_engine_channel_open_respond(channel.0, result as ffi::apt_bool_t);
                    }
                });
            }
            MessageType::Close => unsafe {
                mrcp_engine_channel_close_respond(msg.channel);
            },
            MessageType::RequestProcess => unsafe {
                dispatch_request(msg.channel, msg.request);
            },
        }
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
    task: *mut ffi::apt_task_t,
    msg: *mut ffi::apt_task_msg_t,
) -> ffi::apt_bool_t {
    debug!("Message processing...");

    let consumer_task = ffi::apt_task_object_get(task) as *mut ffi::apt_consumer_task_t;
    let task_data = ffi::apt_consumer_task_object_get(consumer_task) as *mut TaskData;
    let task_data = &mut *task_data;

    // Move the contents pointed to by the `Message` pointer onto the
    // stack. The stack allocated `Message` will be dropped by this
    // Rust plugin, and the heap memory owned by the `apt_task_msg_t`
    // will be freed by the UniMRCP runtime after this function
    // returns.
    let msg = std::ptr::read(&(*msg).data as *const _ as *const Message);

    task_data.process_message(msg);

    ffi::TRUE
}

/// Log in to the Brain service, returning an HTTP client
/// preconfigured with JWT auth credentials.
async fn login(config: Config) -> Result<reqwest::Client, Error> {
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
        .basic_auth(config.brain_username, Some(config.brain_password))
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
