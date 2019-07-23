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
