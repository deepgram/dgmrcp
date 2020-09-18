use crate::{channel::Channel, error::Error, ffi, helper::*};
use serde::Deserialize;
use std::{ffi::CStr, ptr::NonNull, sync::Arc};

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

    let mut runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            error!("failed to create runtime: {}", err);
            return ffi::FALSE;
        }
    };
    let runtime_handle = runtime.handle().clone();

    let (shutdown, rx) = tokio::sync::oneshot::channel();
    let thread_handle = match std::thread::Builder::new()
        .name("DG ASR Engine".to_string())
        .spawn(|| {
            info!("starting tokio runtime");
            runtime.block_on(async {
                info!("started tokio runtime");
                rx.await.ok();
            });
            info!("dropping tokio runtime");
            drop(runtime);
            info!("dropped tokio runtime");
        }) {
        Ok(handle) => handle,
        Err(err) => {
            error!("failed to spawn runtime thread: {}", err);
            return ffi::FALSE;
        }
    };

    (*engine).obj = Box::into_raw(Box::new(Engine {
        config,
        thread_handle,
        runtime_handle,
        shutdown,
    })) as *mut _;

    info!("Opened engine");
    mrcp_engine_open_respond(engine, ffi::TRUE)
}

unsafe extern "C" fn engine_close(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    debug!("Closing the Deepgram ASR Engine");
    let data = Box::from_raw((*engine).obj as *mut Engine);
    (*engine).obj = std::ptr::null_mut();

    data.shutdown.send(()).ok();
    info!("joining scheduler thread");
    data.thread_handle.join().ok();
    info!("joined scheduler thread");
    mrcp_engine_close_respond(engine)
}

unsafe extern "C" fn engine_create_channel(
    engine: *mut ffi::mrcp_engine_t,
    pool: *mut ffi::apr_pool_t,
) -> *mut ffi::mrcp_engine_channel_t {
    let data = &*((*engine).obj as *mut Engine);

    let channel_data = Channel::new(pool, data.config.clone(), data.runtime_handle.clone());
    let channel_data = crate::pool::Pool::from(pool).palloc(channel_data);

    let caps = mpf_sink_stream_capabilities_create(pool);
    let codec: &CStr = CStr::from_bytes_with_nul_unchecked(b"LPCM\0");
    mpf_codec_capabilities_add(
        &mut (*caps).codecs as *mut _,
        (ffi::mpf_sample_rates_e::MPF_SAMPLE_RATE_8000
            | ffi::mpf_sample_rates_e::MPF_SAMPLE_RATE_16000) as i32,
        codec.as_ptr(),
    );

    let termination = ffi::mrcp_engine_audio_termination_create(
        channel_data as *mut _,
        &crate::stream::STREAM_VTABLE,
        caps,
        pool,
    );

    let channel = ffi::mrcp_engine_channel_create(
        engine,
        &Channel::VTABLE,
        channel_data as *mut _,
        termination,
        pool,
    );

    (*channel_data).channel = NonNull::new(channel).unwrap();

    channel
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
    pub model: Option<String>,
    pub language: Option<String>,
    pub sensitivity_level: Option<f32>,
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
    config: Arc<Config>,
    thread_handle: std::thread::JoinHandle<()>,
    runtime_handle: tokio::runtime::Handle,
    shutdown: tokio::sync::oneshot::Sender<()>,
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
