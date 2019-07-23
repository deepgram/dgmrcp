use std::cell::UnsafeCell;
use std::ops::Deref;

/// A transparent representation of a non-const global variable (and a "safer"
/// version of Rust's `static mut`). `UnsafeCell` gets us 90% there, but for
/// the variables to be static (global), they need to be `Sync`.
#[repr(transparent)]
pub struct RacyUnsafeCell<T>(UnsafeCell<T>);

unsafe impl<T> Sync for RacyUnsafeCell<T> {}

impl<T> RacyUnsafeCell<T> {
    pub const fn new(x: T) -> Self {
        Self(UnsafeCell::new(x))
    }
}

impl<T> Deref for RacyUnsafeCell<T> {
    type Target = UnsafeCell<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
