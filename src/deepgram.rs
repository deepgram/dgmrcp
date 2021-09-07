//! Deepgram API and client integration.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct StreamingResponse {
    pub channel_index: (u16, u16),
    pub duration: f32,
    pub start: f32,
    pub is_final: bool,
    pub channel: Channel,
    pub speech_final: bool,
}

#[derive(Debug, Deserialize)]
pub struct Channel {
    pub alternatives: Vec<Alternative>,
}

#[derive(Debug, Deserialize)]
pub struct Alternative {
    pub transcript: String,
    pub confidence: f32,
    pub words: Vec<Word>,
}

#[derive(Debug, Deserialize)]
pub struct Word {
    pub word: String,
    pub start: f32,
    pub end: f32,
    pub confidence: f32,
}

#[derive(Debug, Deserialize)]
pub struct Summary {
    pub transaction_key: String,
    pub request_id: String,
    pub sha256: String,
    pub created: String,
    pub duration: f32,
    pub channels: u16,
}
