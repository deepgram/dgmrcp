use crate::{ffi, utils::cell::RacyUnsafeCell};
use std::ffi::CString;

pub struct Logger;

const LOG_NAME: &str = "DG-ASR";

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(&record.metadata()) {
            unsafe {
                use crate::ffi::apt_log_priority_e::*;
                let priority = match record.level() {
                    log::Level::Error => APT_PRIO_ERROR,
                    log::Level::Warn => APT_PRIO_WARNING,
                    log::Level::Info => APT_PRIO_NOTICE,
                    log::Level::Debug => APT_PRIO_INFO,
                    log::Level::Trace => APT_PRIO_DEBUG,
                };

                let file = CString::new(record.file().unwrap_or("")).unwrap();
                // Internally, apt_log will use this string as a
                // printf style format string, so it's important that
                // we escape `%` characters or else it will try to
                // substitute values from uninitialized memory.
                let format = CString::new(
                    format!("[DG :: {}] {}", record.target(), record.args()).replace("%", "%%"),
                )
                .unwrap();

                ffi::apt_log(
                    *RECOG_PLUGIN.get(),
                    file.as_ptr(),
                    record.line().unwrap_or(0) as i32,
                    priority,
                    format.as_ptr(),
                );
            }
        }
    }

    fn flush(&self) {}
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
