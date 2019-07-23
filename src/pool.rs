use crate::ffi;
pub struct Pool(*mut ffi::apr_pool_t);

impl From<*mut ffi::apr_pool_t> for Pool {
    fn from(ptr: *mut ffi::apr_pool_t) -> Self {
        Self::wrap(ptr)
    }
}

impl Pool {
    pub fn into_inner(self) -> *mut ffi::apr_pool_t {
        self.0
    }

    pub fn wrap(ptr: *mut ffi::apr_pool_t) -> Self {
        Self(ptr)
    }

    pub fn get(&mut self) -> *mut ffi::apr_pool_t {
        self.0
    }
}
