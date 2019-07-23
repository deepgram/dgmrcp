use crate::{engine::{Channel2, Engine}, helper::*, ffi, pool::Pool, codec::Codec, frame::Frame};
use std::mem::ManuallyDrop;

/// Define the engine v-table
pub static STREAM_VTABLE: ffi::mpf_audio_stream_vtable_t = ffi::mpf_audio_stream_vtable_t {
    destroy: Some(stream_destroy),
    open_rx: None,
    close_rx: None,
    read_frame: None,
    open_tx: Some(stream_open),
    close_tx: Some(stream_close),
    write_frame: Some(stream_write),
    trace: None,
};

unsafe extern "C" fn stream_destroy(stream: *mut ffi::mpf_audio_stream_t) -> ffi::apt_bool_t {
    Stream::wrap(stream).destroy();
    ffi::TRUE
}

unsafe extern "C" fn stream_open(stream: *mut ffi::mpf_audio_stream_t, codec: *mut ffi::mpf_codec_t) -> ffi::apt_bool_t {
    Stream::wrap(stream).open(&mut codec.into()) as ffi::apt_bool_t
}

unsafe extern "C" fn stream_close(stream: *mut ffi::mpf_audio_stream_t) -> ffi::apt_bool_t {
    Stream::wrap(stream).close() as ffi::apt_bool_t
}

unsafe extern "C" fn stream_write(
    stream: *mut ffi::mpf_audio_stream_t,
    frame: *const ffi::mpf_frame_t,
) -> ffi::apt_bool_t {
    Stream::wrap(stream)
        .write(&mut frame.into()) as ffi::apt_bool_t
}

pub struct Stream(*mut ffi::mpf_audio_stream_t);

impl From<*mut ffi::mpf_audio_stream_t> for Stream {
    fn from(ptr: *mut ffi::mpf_audio_stream_t) -> Self {
        Self::wrap(ptr)
    }
}

impl Stream {
    fn wrap(ptr: *mut ffi::mpf_audio_stream_t) -> Self {
        Self(ptr)
    }

    pub fn into_inner(self) -> *mut ffi::mpf_audio_stream_t {
        self.0
    }

    fn destroy(self) {
        debug!("Destroying a Deepgram ASR Stream.");
        unimplemented!()
    }

    fn open(&mut self, codec: &mut Codec) -> bool {
        debug!("Opening a Deepgram ASR Stream.");
        true
    }

    fn close(&mut self) -> bool {
        debug!("Closing a Deepgram ASR Stream.");
        true
    }

    fn write(&mut self, frame: &mut Frame) -> bool {
        debug!("Writing to stream.");
        let mut recog_channel = ManuallyDrop::new(unsafe {
            Box::from_raw((*self.0).obj as *mut Channel2)
        });
        if let Some(stop_response) = recog_channel.stop_response.take() {
            unsafe { mrcp_engine_channel_message_send(recog_channel.channel.unwrap(), stop_response) };
            recog_channel.recog_request.take();
            return true;
        }

        if let Some(recog_request) = recog_channel.recog_request {
            match unsafe { ffi::mpf_activity_detector_process(recog_channel.detector.unwrap(), frame.get()) } {
                ffi::mpf_detector_event_e::MPF_DETECTOR_EVENT_ACTIVITY => {
                    debug!("Detected voice activity.");
                    recog_channel.start_of_input();
                }
                ffi::mpf_detector_event_e::MPF_DETECTOR_EVENT_INACTIVITY => {
                    debug!("Detected voice inactivity.");
                    recog_channel.recognition_complete(ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS);
                }
                ffi::mpf_detector_event_e::MPF_DETECTOR_EVENT_NOINPUT => {
                    debug!("Detected no input.");
                    if recog_channel.timers_started == ffi::TRUE {
                        recog_channel.recognition_complete(ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_NO_INPUT_TIMEOUT);
                    }
                }
                _ => (),
            }
            
            if let Some(recog_request) = recog_channel.recog_request {
                if (frame.get().type_ & ffi::mpf_frame_type_e::MEDIA_FRAME_TYPE_EVENT as i32) == ffi::mpf_frame_type_e::MEDIA_FRAME_TYPE_EVENT as i32 {
                    if frame.get().marker == ffi::mpf_frame_marker_e::MPF_MARKER_START_OF_EVENT as i32 {
                        debug!("Detected start of event.");
                    } else if frame.get().marker == ffi::mpf_frame_marker_e::MPF_MARKER_END_OF_EVENT as i32 {
                        debug!("Detected start of event.");
                    }
                }
            }

            debug!("Received {} bytes of audio.", frame.get().codec_frame.size);
        }
        true
    }
}
