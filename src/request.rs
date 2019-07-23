use crate::ffi;

pub struct Request(*mut ffi::mrcp_message_t);

impl From<*mut ffi::mrcp_message_t> for Request {
    fn from(ptr: *mut ffi::mrcp_message_t) -> Self {
        Self::wrap(ptr)
    }
}

impl Request {
    pub fn into_inner(self) -> *mut ffi::mrcp_message_t {
        self.0
    }

    pub fn wrap(ptr: *mut ffi::mrcp_message_t) -> Self {
        Self(ptr)
    }

    pub fn get(&mut self) -> *mut ffi::mrcp_message_t {
        self.0
    }
}
