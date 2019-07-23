use crate::{
    channel::{recognize_channel, Channel},
    ffi,
    helper::*,
};
use std::mem;

#[derive(Debug, Copy, Clone)]
pub enum MessageType {
    Open,
    Close,
    RequestProcess,
}

pub struct Message {
    pub message_type: MessageType,
    pub channel: *mut ffi::mrcp_engine_channel_t,
    pub request: *mut ffi::mrcp_message_t,
}

pub(crate) unsafe fn dispatch_request(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    debug!("Dispatching message.");
    let response = ffi::mrcp_response_create(request, (*request).pool);
    let processed = match ((*request).start_line).method_id as u32 {
        ffi::mrcp_recognizer_method_id::RECOGNIZER_RECOGNIZE => {
            recognize_channel(channel, request, response) != 0
        }
        ffi::mrcp_recognizer_method_id::RECOGNIZER_START_INPUT_TIMERS => {
            {
                let mut channel =
                    mem::ManuallyDrop::new(Box::from_raw((*channel).method_obj as *mut Channel));
                channel.timers_started = ffi::TRUE;
            }
            mrcp_engine_channel_message_send(channel, response) != 0
        }
        ffi::mrcp_recognizer_method_id::RECOGNIZER_STOP => {
            let mut channel =
                mem::ManuallyDrop::new(Box::from_raw((*channel).method_obj as *mut Channel));
            channel.stop_response = Some(response);
            true
        }
        _ => false,
    };
    if !processed {
        mrcp_engine_channel_message_send(channel, response);
    }
    ffi::TRUE
}
