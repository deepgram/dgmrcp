use crate::ffi;
use std::ptr::NonNull;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum MessageType {
    Open {
        rx: mpsc::Receiver<tungstenite::Message>,
        sample_rate: u16,
        channels: u8,
    },
    Close,
    RequestProcess {
        request: NonNull<ffi::mrcp_message_t>,
    },
}

pub struct Message {
    pub message_type: MessageType,
    pub channel: NonNull<ffi::mrcp_engine_channel_t>,
}
