use crate::{
    channel::{recognize_channel, Channel},
    ffi,
    helper::*,
};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum MessageType {
    Open {
        rx: mpsc::Receiver<tungstenite::Message>,
        sample_rate: u16,
        channels: u8,
    },
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
    debug!("Dispatching message {}", ((*request).start_line).method_id);
    let response = ffi::mrcp_response_create(request, (*request).pool);
    let processed = match ((*request).start_line).method_id as u32 {
        ffi::mrcp_recognizer_method_id::RECOGNIZER_RECOGNIZE => {
            recognize_channel(channel, request, response) != 0
        }
        ffi::mrcp_recognizer_method_id::RECOGNIZER_START_INPUT_TIMERS => {
            {
                let channel = &mut *((*channel).method_obj as *mut Channel);
                channel.timers_started = ffi::TRUE;
            }
            mrcp_engine_channel_message_send(channel, response) != 0
        }
        ffi::mrcp_recognizer_method_id::RECOGNIZER_STOP => {
            info!("Received STOP message");
            let channel = &mut *((*channel).method_obj as *mut Channel);
            channel.stop_response = Some(response);
            true
        }
        // TODO: These are probably useful to implement.
        ffi::mrcp_recognizer_method_id::RECOGNIZER_SET_PARAMS => false,
        ffi::mrcp_recognizer_method_id::RECOGNIZER_GET_PARAMS => false,
        _ => false,
    };
    if !processed {
        mrcp_engine_channel_message_send(channel, response);
    }
    ffi::TRUE
}
