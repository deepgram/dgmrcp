use crate::ffi;

pub struct Pool(*mut ffi::apr_pool_t);

// TODO: Not sure if this is okay -- I think this should be unsafe.
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

    /// Move an already constructed object into the memory pool.
    pub fn palloc<T>(&mut self, src: T) -> *mut T {
        unsafe {
            let ptr: *mut T = ffi::apr_palloc(self.get(), std::mem::size_of::<T>()) as *mut _;
            ptr.copy_from_nonoverlapping(&src as *const _, 1);
            std::mem::forget(src);
            ptr
        }
    }

    /// Move an object out of the memory pool. This allows the object
    /// to be dropped, and the memory to be simply deallocated.
    pub fn take<T>(ptr: &mut *mut T) -> T {
        todo!()
    }
}
