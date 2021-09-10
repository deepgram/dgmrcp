use crate::{channel::Channel, ffi, helper::*};
use std::sync::{Arc, Mutex};

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
    info!("stream_destroy");
    Stream::wrap(stream).destroy();
    ffi::TRUE
}

unsafe extern "C" fn stream_open(
    stream: *mut ffi::mpf_audio_stream_t,
    _codec: *mut ffi::mpf_codec_t,
) -> ffi::apt_bool_t {
    info!("stream_open");
    Stream::wrap(stream).open() as ffi::apt_bool_t
}

unsafe extern "C" fn stream_close(stream: *mut ffi::mpf_audio_stream_t) -> ffi::apt_bool_t {
    info!("stream_close");
    Stream::wrap(stream).close() as ffi::apt_bool_t
}

unsafe extern "C" fn stream_write(
    stream: *mut ffi::mpf_audio_stream_t,
    frame: *const ffi::mpf_frame_t,
) -> ffi::apt_bool_t {
    Stream::wrap(stream).write(&*frame) as ffi::apt_bool_t
}

pub struct Stream(*mut ffi::mpf_audio_stream_t);

impl Stream {
    fn wrap(ptr: *mut ffi::mpf_audio_stream_t) -> Self {
        Self(ptr)
    }

    fn destroy(self) {
        debug!("Destroying a Deepgram ASR Stream.");
        unimplemented!()
    }

    fn open(&mut self) -> bool {
        debug!("Opening a Deepgram ASR Stream; direction = {:x}", unsafe {
            (*self.0).direction
        });
        true
    }

    fn close(&mut self) -> bool {
        debug!("Closing a Deepgram ASR Stream.");
        true
    }

    fn write(&mut self, frame: &ffi::mpf_frame_t) -> bool {
        trace!("write :: frame.type={}", frame.type_);

        let recog_channel = unsafe { &mut *((*self.0).obj as *mut Arc<Mutex<Channel>>) };
        let mut recog_channel = recog_channel.lock().unwrap();

        // TODO: What is this for?
        if let Some(stop_response) = recog_channel.stop_response.take() {
            debug!("Received stop response");
            unsafe {
                mrcp_engine_channel_message_send(recog_channel.channel.as_ptr(), stop_response)
            };
            recog_channel.recog_request.take();
            return true;
        }

        if recog_channel.recog_request.is_none() {
            return true;
        }

        // We only need to check the activity detector if we have not
        // yet received results from the backend; if results have been
        // received, then we rely on the backend's endpointing.
        if let Some(detector) = recog_channel
            .detector
            .activity_detector
            .filter(|_| !recog_channel.detector.speaking)
        {
            let event = unsafe { ffi::mpf_activity_detector_process(detector.as_ptr(), frame) };
            match event {
                ffi::mpf_detector_event_e::MPF_DETECTOR_EVENT_ACTIVITY => {
                    debug!("Detected voice activity.");
                    // TODO: If the activity detector gets triggered,
                    // then this will cause us to never update it
                    // again, because we assume that we'll be
                    // receiving ASR results. If we _don't_ receive
                    // ASR results, then this we'll end up waiting
                    // forever.
                    recog_channel.detector.speaking = true;
                    recog_channel.start_of_input();
                }
                ffi::mpf_detector_event_e::MPF_DETECTOR_EVENT_INACTIVITY => {
                    debug!("Detected voice inactivity.");
                    if let Err(_) = recog_channel.flush() {
                        return false;
                    }
                    recog_channel.end_of_input(
                        ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS,
                    );
                }
                ffi::mpf_detector_event_e::MPF_DETECTOR_EVENT_NOINPUT => {
                    debug!("Detected no input.");
                    if let Err(_) = recog_channel.flush() {
                        return false;
                    }
                    if recog_channel.timers_started == ffi::TRUE {
                        recog_channel.end_of_input(ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_NO_INPUT_TIMEOUT);
                    }
                }
                ffi::mpf_detector_event_e::MPF_DETECTOR_EVENT_NONE => (),
                _ => warn!("unhandled event type: {}", event),
            }
        }

        if (frame.type_ & ffi::mpf_frame_type_e::MEDIA_FRAME_TYPE_EVENT as i32)
            == ffi::mpf_frame_type_e::MEDIA_FRAME_TYPE_EVENT as i32
        {
            if frame.marker == ffi::mpf_frame_marker_e::MPF_MARKER_START_OF_EVENT as i32 {
                debug!("Detected start of event.");
            } else if frame.marker == ffi::mpf_frame_marker_e::MPF_MARKER_END_OF_EVENT as i32 {
                debug!("Detected end of event.");
            }
        }

        if frame.type_ & ffi::mpf_frame_type_e::MEDIA_FRAME_TYPE_AUDIO as i32 != 0 {
            trace!("Received {} bytes of audio.", frame.codec_frame.size);
            recog_channel
                .buffer
                .extend_from_slice(frame.codec_frame.as_slice());
            if let Err(_) = recog_channel.flush() {
                return false;
            }
        }

        true
    }
}
