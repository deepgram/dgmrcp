use crate::{channel::Channel, ffi, helper::*};
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

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => Arc::new(runtime),
        Err(err) => {
            error!("failed to create runtime: {}", err);
            return ffi::FALSE;
        }
    };

    (*engine).obj = Box::into_raw(Box::new(Engine { config, runtime })) as *mut _;

    info!("Opened engine");
    mrcp_engine_open_respond(engine, ffi::TRUE)
}

unsafe extern "C" fn engine_close(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    debug!("Closing the Deepgram ASR Engine");
    let data = Box::from_raw((*engine).obj as *mut Engine);
    (*engine).obj = std::ptr::null_mut();

    if let Ok(runtime) = Arc::try_unwrap(data.runtime) {
        info!("shutting down tokio runtime");
        runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    } else {
        warn!("there are outstanding tokio runtime handles; it may be dropped from another thread");
    }

    mrcp_engine_close_respond(engine)
}

unsafe extern "C" fn engine_create_channel(
    engine: *mut ffi::mrcp_engine_t,
    pool: *mut ffi::apr_pool_t,
) -> *mut ffi::mrcp_engine_channel_t {
    let data = &*((*engine).obj as *mut Engine);

    // Construct a new channel, box it, and leak the pointer. The box
    // will be reconstructed when the channel closes, and the
    // `Channel` will be deallocated correctly.
    let channel_data = Channel::new(pool, data.config.clone(), data.runtime.clone());
    let channel_data = Box::into_raw(Box::new(channel_data));

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

    (*channel_data).lock().unwrap().channel = NonNull::new(channel).unwrap();

    channel
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub brain_url: url::Url,
    pub brain_username: Option<String>,
    pub brain_password: Option<String>,
    #[serde(default = "Config::default_chunk_size")]
    pub chunk_size: u64,
    #[serde(default)]
    pub stream_results: bool,
    #[serde(default)]
    pub plaintext_results: bool,
    pub model: Option<String>,
    pub language: Option<String>,
    pub sensitivity_level: Option<f32>,

    // These should be considered instantly deprecated.
    //
    // What we really need is a general way to insert arbitrary query
    // parameters, but this allows us to unblock someone right now.
    pub numerals: Option<bool>,
    pub ner: Option<bool>,
    pub no_delay: Option<bool>,
    pub plugin: Option<String>,
    pub keywords: Option<String>,
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
    runtime: Arc<tokio::runtime::Runtime>,
}

/*
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
*/
