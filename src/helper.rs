use crate::ffi;
use std::ffi::c_void;
use std::ptr;

/// Convenience function, reimplemented from the `static` C function of the same name.
pub unsafe fn mrcp_engine_open_respond(
    engine: *mut ffi::mrcp_engine_t,
    status: ffi::apt_bool_t,
) -> ffi::apt_bool_t {
    ((*(*engine).event_vtable).on_open.unwrap())(engine, status)
}

/// Convenience function, reimplemented from the `static` C function of the same name.
pub unsafe fn mrcp_engine_close_respond(engine: *mut ffi::mrcp_engine_t) -> ffi::apt_bool_t {
    ((*(*engine).event_vtable).on_close.unwrap())(engine)
}

pub unsafe fn mpf_sink_stream_capabilities_create(
    pool: *mut ffi::apr_pool_t,
) -> *mut ffi::mpf_stream_capabilities_t {
    ffi::mpf_stream_capabilities_create(ffi::mpf_stream_direction_e::STREAM_DIRECTION_SEND, pool)
}

pub unsafe fn mpf_codec_capabilities_add(
    capabilities: *mut ffi::mpf_codec_capabilities_t,
    sample_rates: i32,
    codec_name: *const i8,
) -> ffi::apt_bool_t {
    let attribs: *mut ffi::mpf_codec_attribs_t =
        ffi::apr_array_push((*capabilities).attrib_arr) as *mut _;
    apt_string_assign(
        &mut (*attribs).name as *mut _,
        codec_name,
        (*(*capabilities).attrib_arr).pool,
    );
    (*attribs).sample_rates = sample_rates;
    (*attribs).bits_per_sample = 0;
    ffi::TRUE
}

pub unsafe fn c_strlen(mut x: *const i8) -> usize {
    let mut i = 0;
    loop {
        if *x == 0 {
            break;
        }
        x = x.offset(1);
        i += 1;
    }
    i
}

pub unsafe fn apt_string_assign(
    x: *mut ffi::apt_str_t,
    src: *const i8,
    pool: *mut ffi::apr_pool_t,
) {
    (*x).buf = ptr::null_mut();
    (*x).length = if src.is_null() { 0 } else { c_strlen(src) };
    if (*x).length > 0 {
        (*x).buf = ffi::apr_pstrmemdup(pool, src, (*x).length);
    }
}

pub unsafe fn apt_string_assign_n(
    x: *mut ffi::apt_str_t,
    src: *const i8,
    length: ffi::apr_size_t,
    pool: *mut ffi::apr_pool_t,
) {
    (*x).buf = ptr::null_mut();
    (*x).length = length;
    if (*x).length > 0 {
        (*x).buf = ffi::apr_pstrmemdup(pool, src, (*x).length);
    }
}

pub unsafe fn mrcp_engine_channel_open_respond(
    channel: *mut ffi::mrcp_engine_channel_t,
    status: ffi::apt_bool_t,
) -> ffi::apt_bool_t {
    (*(*channel).event_vtable).on_open.unwrap()(channel, status)
}

pub unsafe fn mrcp_engine_channel_close_respond(
    channel: *mut ffi::mrcp_engine_channel_t,
) -> ffi::apt_bool_t {
    (*(*channel).event_vtable).on_close.unwrap()(channel)
}

pub unsafe fn mrcp_engine_channel_message_send(
    channel: *mut ffi::mrcp_engine_channel_t,
    message: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    (*(*channel).event_vtable).on_message.unwrap()(channel, message)
}

pub unsafe fn mrcp_resource_header_prepare(message: *mut ffi::mrcp_message_t) -> *mut c_void {
    mrcp_header_allocate(
        &mut (*message).header.resource_header_accessor as *mut _,
        (*message).pool,
    )
}

pub unsafe fn mrcp_header_allocate(
    accessor: *mut ffi::mrcp_header_accessor_t,
    pool: *mut ffi::apr_pool_t,
) -> *mut c_void {
    if !(*accessor).data.is_null() {
        (*accessor).data
    } else if (*accessor).vtable.is_null() || (*(*accessor).vtable).allocate.is_none() {
        ptr::null_mut() as *mut c_void
    } else {
        (*(*accessor).vtable).allocate.unwrap()(accessor, pool)
    }
}

pub unsafe fn mrcp_generic_header_prepare(
    message: *mut ffi::mrcp_message_t,
) -> *mut ffi::mrcp_generic_header_t {
    mrcp_header_allocate(
        &mut (*message).header.generic_header_accessor as *mut _,
        (*message).pool,
    ) as *mut ffi::mrcp_generic_header_t
}

pub unsafe fn mrcp_resource_header_get(message: *const ffi::mrcp_message_t) -> *mut c_void {
    (*message).header.resource_header_accessor.data
}

pub unsafe fn mrcp_resource_header_property_check(
    message: *const ffi::mrcp_message_t,
    id: ffi::mrcp_recognizer_header_id::Type,
) -> bool {
    apt_header_section_field_check(
        &(*message).header.header_section as *const _,
        id + ffi::mrcp_generic_header_id::GENERIC_HEADER_COUNT,
    ) == ffi::TRUE
}

pub unsafe fn apt_header_section_field_check(
    header: *const ffi::apt_header_section_t,
    id: ffi::mrcp_recognizer_header_id::Type,
) -> ffi::apt_bool_t {
    if (id as usize) < (*header).arr_size {
        if (*(*header).arr.add(id as usize)).is_null() {
            ffi::FALSE
        } else {
            ffi::TRUE
        }
    } else {
        ffi::FALSE
    }
}
