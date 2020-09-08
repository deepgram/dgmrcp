//! A Deepgram ASR plugin for UniMRCP.
//!
//! # How It Works
//!
//! UniMRCP plugins must do these things:
//!
//! 1. Implement the plugin ("engine") creator function:
//!    `mrcp_engine_t* mrcp_plugin_create(apr_pool_t *pool)`
//! 2. Declare its version number using `MRCP_PLUGIN_VERSION_DECLARE`.
//!
//! # Usage:
//!
//! 1. Copy the compiled plugin (`libdgmrcp.so`) into the UniMRCP plugin
//!    directory, usually: `/usr/local/unimrcp/plugin`.
//! 2. Edit the server configuration file (usually at
//!    `/usr/local/unimrcp/conf/unimrcpserver.xml`). Under the `plugin-factory`
//!    section, make sure you have a field like this:
//!
//!      <engine id="Deepgram" name="libdgmrcp" enable="true"/>
//!
//! # Return values
//!
//! Data is returned as XML (application/x-nlsml). See [RFC
//! 6787](https://tools.ietf.org/html/rfc6787#section-9.6.3.3) for more
//! details.

#[macro_use]
extern crate log;

pub mod channel;
pub mod codec;
pub mod config;
pub mod engine;
pub mod error;
pub mod frame;
pub mod helper;
pub mod logging;
pub mod message;
pub mod pool;
pub mod stem;
pub mod stream;
pub mod utils;

/// Import the MRCP Engine bindings.
pub mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    pub const TRUE: apt_bool_t = 1;
}

/// The functional equivalent of `MRCP_PLUGIN_VERSION_DECLARE`.
#[no_mangle]
pub static mut mrcp_plugin_version: ffi::mrcp_plugin_version_t = ffi::mrcp_plugin_version_t {
    major: ffi::PLUGIN_MAJOR_VERSION as i32,
    minor: ffi::PLUGIN_MINOR_VERSION as i32,
    patch: ffi::PLUGIN_PATCH_VERSION as i32,
    is_dev: 0,
};

/// Create the engine.
#[no_mangle]
pub extern "C" fn mrcp_plugin_create(pool: *mut ffi::apr_pool_t) -> *mut ffi::mrcp_engine_t {
    // Initialize a logging backend that forwards to UniMRCP's logging
    // framework.
    match log::set_logger(&logging::Logger) {
        Err(err) => eprintln!("FAILED TO SET LOGGER: {}", err),
        Ok(()) => log::set_max_level(log::LevelFilter::max()),
    }

    info!("plugin create");

    unsafe {
        ffi::mrcp_engine_create(
            ffi::mrcp_resource_type_e::MRCP_RECOGNIZER_RESOURCE as usize,
            std::ptr::null_mut(),
            &engine::ENGINE_VTABLE as *const _,
            pool,
        )
    }
}
