use crate::{ffi, utils::cell::RacyUnsafeCell};
use std::ffi::CString;

const LOG_NAME: &str = "DG-ASR";

#[doc(hidden)]
#[macro_export]
macro_rules! log {
    ( $priority:expr, $( $x:expr ),* ) => {
        unsafe {
            use std::ffi::CString;
            ffi::apt_log(
                *$crate::logging::RECOG_PLUGIN.get(),
                CString::new(file!()).unwrap().as_ptr(),
                line!() as i32,
                $priority,
                CString::new(format!($( $x ), *)).unwrap().as_ptr(),
            )
        }
    }
}

#[macro_export]
macro_rules! trace {
    ( $( $x:expr ),* ) => {
        $crate::log!($crate::ffi::apt_log_priority_e::APT_PRIO_DEBUG, $( $x ), *)
    }
}

#[macro_export]
macro_rules! debug {
    ( $( $x:expr ),* ) => {
        $crate::log!($crate::ffi::apt_log_priority_e::APT_PRIO_INFO, $( $x ), *)
    }
}

#[macro_export]
macro_rules! info {
    ( $( $x:expr ),* ) => {
        $crate::log!($crate::ffi::apt_log_priority_e::APT_PRIO_NOTICE, $( $x ), *)
    }
}

#[macro_export]
macro_rules! warn {
    ( $( $x:expr ),* ) => {
        $crate::log!($crate::ffi::apt_log_priority_e::APT_PRIO_WARNING, $( $x ), *)
    }
}

#[macro_export]
macro_rules! error {
    ( $( $x:expr ),* ) => {
        $crate::log!($crate::ffi::apt_log_priority_e::APT_PRIO_ERROR, $( $x ), *)
    }
}

/// The functional equivalent of `MRCP_PLUGIN_LOG_SOURCE_IMPLEMENT`.
#[no_mangle]
pub static RECOG_PLUGIN: RacyUnsafeCell<*mut ffi::apt_log_source_t> =
    unsafe { RacyUnsafeCell::new(&ffi::def_log_source as *const _ as *mut _) };
#[no_mangle]
pub unsafe extern "C" fn mrcp_plugin_logger_set(logger: *mut ffi::apt_logger_t) -> ffi::apt_bool_t {
    ffi::apt_log_instance_set(logger);
    ffi::TRUE
}
#[no_mangle]
pub unsafe extern "C" fn mrcp_plugin_log_source_set(orig_log_source: *mut ffi::apt_log_source_t) {
    let name = CString::new(LOG_NAME).unwrap();
    ffi::apt_def_log_source_set(orig_log_source);
    ffi::apt_log_source_assign(name.as_ptr(), RECOG_PLUGIN.get());
}
