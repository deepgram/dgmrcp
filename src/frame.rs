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

    /// Access the codec frame as a byte slice.
    pub fn codec_frame(&self) -> &[u8] {
        unsafe {
            // TODO: Is the pointer ever null? Is the size ever 0? Do
            // we need to return something else in that case?

            std::slice::from_raw_parts(
                (*self.0).codec_frame.buffer as *const _,
                (*self.0).codec_frame.size,
            )
        }
    }
}
