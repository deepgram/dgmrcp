use crate::ffi;

pub struct Codec(*mut ffi::mpf_codec_t);

impl From<*mut ffi::mpf_codec_t> for Codec {
    fn from(ptr: *mut ffi::mpf_codec_t) -> Self {
        Self::wrap(ptr)
    }
}

impl Codec {
    pub fn into_inner(self) -> *mut ffi::mpf_codec_t {
        self.0
    }

    pub fn wrap(ptr: *mut ffi::mpf_codec_t) -> Self {
        Self(ptr)
    }

    pub fn get(&mut self) -> *mut ffi::mpf_codec_t {
        self.0
    }
}
