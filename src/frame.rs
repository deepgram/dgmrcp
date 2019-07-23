use crate::ffi;
pub struct Frame(*const ffi::mpf_frame_t);

impl From<*const ffi::mpf_frame_t> for Frame {
    fn from(ptr: *const ffi::mpf_frame_t) -> Self {
        Self::wrap(ptr)
    }
}

impl Frame {
    pub fn into_inner(self) -> *const ffi::mpf_frame_t {
        self.0
    }

    pub fn wrap(ptr: *const ffi::mpf_frame_t) -> Self {
        Self(ptr)
    }

    pub fn get(&self) -> &ffi::mpf_frame_t {
        unsafe { &*self.0 }
    }
}
