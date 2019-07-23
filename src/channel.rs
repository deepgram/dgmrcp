use crate::{engine::Engine, ffi, pool::Pool, request::Request};

/// Define the engine v-table
pub static CHANNEL_VTABLE: ffi::mrcp_engine_channel_method_vtable_t = ffi::mrcp_engine_channel_method_vtable_t {
    destroy: Some(channel_destroy),
    open: Some(channel_open),
    close: Some(channel_close),
    process_request: Some(channel_process_request),
};

unsafe extern "C" fn channel_destroy(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    Channel::wrap(channel).destroy();
    ffi::TRUE
}

unsafe extern "C" fn channel_open(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    Channel::wrap(channel).open() as ffi::apt_bool_t
}

unsafe extern "C" fn channel_close(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    Channel::wrap(channel).close() as ffi::apt_bool_t
}

unsafe extern "C" fn channel_process_request(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    Channel::wrap(channel)
        .process_request(&mut request.into()) as ffi::apt_bool_t
}

pub struct Channel(*mut ffi::mrcp_engine_channel_t);

impl From<*mut ffi::mrcp_engine_channel_t> for Channel {
    fn from(ptr: *mut ffi::mrcp_engine_channel_t) -> Self {
        Self::wrap(ptr)
    }
}

impl Channel {
    pub fn new(engine: &mut Engine, pool: &mut Pool) -> Self {
        unimplemented!()
    }

    fn wrap(ptr: *mut ffi::mrcp_engine_channel_t) -> Self {
        Self(ptr)
    }

    pub fn into_inner(self) -> *mut ffi::mrcp_engine_channel_t {
        self.0
    }

    fn destroy(self) {
        debug!("Destroying a Deepgram ASR Channel.");
        unimplemented!()
    }

    fn open(&mut self) -> bool {
        debug!("Opening a Deepgram ASR Channel.");
        true
    }

    fn close(&mut self) -> bool {
        debug!("Closing a Deepgram ASR Channel.");
        true
    }

    fn process_request(&mut self, request: &mut Request) -> bool {
        unimplemented!()
    }
}
