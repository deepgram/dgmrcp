use crate::{
    engine::Engine, error::Error, ffi, helper::*, message::*, pool::Pool, stem::StreamingResponse,
    stream::STREAM_VTABLE,
};
use std::{
    ffi::{CStr, CString},
    mem, ptr,
};
use tokio::sync::mpsc;

#[repr(C)]
pub struct Channel {
    pub engine: *mut Engine,
    pub channel: *mut ffi::mrcp_engine_channel_t,
    pub recog_request: Option<*mut ffi::mrcp_message_t>,
    pub stop_response: Option<*mut ffi::mrcp_message_t>,
    pub timers_started: ffi::apt_bool_t,
    pub detector: Option<*mut ffi::mpf_activity_detector_t>,
    pub sink: Option<mpsc::Sender<tungstenite::Message>>,
}

impl Channel {
    pub(crate) fn alloc(
        engine: *mut ffi::mrcp_engine_t,
        pool: &mut Pool,
    ) -> Result<*mut ffi::mrcp_engine_channel_t, Error> {
        info!("Constructing a Deepgram ASR Engine Channel.");
        let data = Self {
            engine: unsafe { *engine }.obj as *mut _,
            recog_request: None,
            stop_response: None,
            detector: Some(unsafe { ffi::mpf_activity_detector_create(pool.get()) }),
            timers_started: ffi::FALSE as i32,
            channel: ptr::null_mut(),
            sink: None,
        };
        let data = pool.palloc(data);

        let caps = unsafe { mpf_sink_stream_capabilities_create(pool.get()) };
        let codec: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"LPCM\0") };
        unsafe {
            mpf_codec_capabilities_add(
                &mut (*caps).codecs as *mut _,
                (ffi::mpf_sample_rates_e::MPF_SAMPLE_RATE_8000
                    | ffi::mpf_sample_rates_e::MPF_SAMPLE_RATE_16000) as i32,
                codec.as_ptr(),
            );
        }

        let termination = unsafe {
            ffi::mrcp_engine_audio_termination_create(
                data as *mut _,
                &STREAM_VTABLE,
                caps,
                pool.get(),
            )
        };

        let channel = unsafe {
            ffi::mrcp_engine_channel_create(
                engine,
                &CHANNEL_VTABLE,
                data as *mut _,
                termination,
                pool.get(),
            )
        };

        unsafe {
            (*data).channel = channel;
        }

        Ok(channel)
    }

    pub fn start_of_input(&mut self) -> bool {
        debug!("Start-of-input.");
        let message = unsafe {
            ffi::mrcp_event_create(
                self.recog_request.unwrap() as *const _,
                ffi::mrcp_recognizer_event_id::RECOGNIZER_START_OF_INPUT as usize,
                (*self.recog_request.unwrap()).pool,
            )
        };

        if message.is_null() {
            false
        } else {
            unsafe {
                (*message).start_line.request_state =
                    ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
                mrcp_engine_channel_message_send(self.channel, message) != 0
            }
        }
    }

    pub fn results_available(&mut self, response: StreamingResponse) {
        info!(
            "Results available (FINAL={}): {}",
            response.is_final,
            response
                .channel
                .alternatives
                .get(0)
                .map(|alt| alt.transcript.as_str())
                .unwrap_or("<< NO RESULTS >>")
        );

        let message = unsafe {
            ffi::mrcp_event_create(
                self.recog_request.unwrap() as *const _,
                ffi::mrcp_recognizer_event_id::RECOGNIZER_RECOGNITION_COMPLETE as usize,
                (*self.recog_request.unwrap()).pool,
            )
        };
    }

    pub fn recognition_complete(
        &mut self,
        cause: ffi::mrcp_recog_completion_cause_e::Type,
    ) -> bool {
        debug!("Recognition complete.");

        let message = unsafe {
            ffi::mrcp_event_create(
                self.recog_request.unwrap() as *const _,
                ffi::mrcp_recognizer_event_id::RECOGNIZER_RECOGNITION_COMPLETE as usize,
                (*self.recog_request.unwrap()).pool,
            )
        };

        if message.is_null() {
            return false;
        }

        let header =
            unsafe { mrcp_resource_header_prepare(message) as *mut ffi::mrcp_recog_header_t };
        if !header.is_null() {
            unsafe {
                (*header).completion_cause = cause;
                ffi::mrcp_resource_header_property_add(
                    message,
                    ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_COMPLETION_CAUSE as usize,
                );
            }
        }

        unsafe {
            (*message).start_line.request_state =
                ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_COMPLETE;
        }

        if cause == ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS {
            unsafe {
                let body = CString::new(
                    br#"<?xml version="1.0"?>
<result> 
  <interpretation grammar="session:request1@form-level.store" confidence="0.97">
    <instance>one</instance>
    <input mode="speech">one</input>
  </interpretation>
</result>
"#
                    .to_vec(),
                )
                .unwrap();
                apt_string_assign_n(
                    &mut (*message).body,
                    body.as_ptr(),
                    body.to_bytes().len(),
                    (*message).pool,
                );
            }

            let header = unsafe { mrcp_generic_header_prepare(message) };
            if !header.is_null() {
                unsafe {
                    let content_type =
                        CStr::from_bytes_with_nul_unchecked(b"application/x-nlsml\0");
                    apt_string_assign(
                        &mut (*header).content_type,
                        content_type.as_ptr(),
                        (*message).pool,
                    );
                    ffi::mrcp_generic_header_property_add(
                        message,
                        ffi::mrcp_generic_header_id::GENERIC_HEADER_CONTENT_TYPE as usize,
                    );
                }
            }
        }

        self.recog_request.take();

        unsafe { mrcp_engine_channel_message_send(self.channel, message) != 0 }
    }
}

/// Define the engine v-table
static CHANNEL_VTABLE: ffi::mrcp_engine_channel_method_vtable_t =
    ffi::mrcp_engine_channel_method_vtable_t {
        destroy: Some(channel_destroy),
        open: Some(channel_open),
        close: Some(channel_close),
        process_request: Some(channel_process_request),
    };

unsafe extern "C" fn channel_destroy(_channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    debug!("Destroying Deepgram ASR channel.");
    ffi::TRUE
}

unsafe extern "C" fn channel_open(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    debug!("Opening Deepgram ASR channel.");
    let (tx, rx) = mpsc::channel(8);
    let channel_data = &mut *((*channel).method_obj as *mut Channel);
    channel_data.sink = Some(tx);
    msg_signal(MessageType::Open { rx }, channel, ptr::null_mut())
}

unsafe extern "C" fn channel_close(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    debug!("Closing Deepgram ASR channel.");

    let channel_data = &mut *((*channel).method_obj as *mut Channel);
    channel_data.sink.take();

    msg_signal(MessageType::Close, channel, ptr::null_mut())
}

unsafe extern "C" fn channel_process_request(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    msg_signal(MessageType::RequestProcess, channel, request)
}

unsafe fn msg_signal(
    message_type: MessageType,
    channel_ptr: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    debug!("Message signal: {:?}", message_type);
    let channel = &mut *((*channel_ptr).method_obj as *mut Channel);
    let engine = channel.engine;
    let task = ffi::apt_consumer_task_base_get((*engine).task.unwrap());
    let msg_ptr = ffi::apt_task_msg_get(task);
    if !msg_ptr.is_null() {
        let msg = &mut (*msg_ptr).data as *mut _ as *mut Message;
        std::ptr::write(
            msg,
            Message {
                message_type,
                channel: channel_ptr,
                request,
            },
        );

        // (*msg_ptr).type_ = ffi::apt_task_msg_type_e::TASK_MSG_USER as i32;
        // let mut msg = &mut *(&mut (*msg_ptr).data as *mut _ as *mut Message);
        // msg.message_type = message_type;
        // msg.channel = channel_ptr;
        // msg.request = request;
        ffi::apt_task_msg_signal(task, msg_ptr)
    } else {
        ffi::FALSE as i32
    }
}

pub(crate) unsafe fn recognize_channel(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
    response: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    debug!("Channel recognize.");
    // TODO: Get rid of manually drop
    let mut recog_channel =
        mem::ManuallyDrop::new(Box::from_raw((*channel).method_obj as *mut Channel));
    let descriptor = ffi::mrcp_engine_sink_stream_codec_get(channel);

    if descriptor.is_null() {
        warn!("Failed to get codec description.");
        (*response).start_line.status_code =
            ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;
        return ffi::FALSE as i32;
    }

    recog_channel.timers_started = ffi::TRUE;

    let recog_header = mrcp_resource_header_get(request) as *mut ffi::mrcp_recog_header_t;
    if !recog_header.is_null() {
        if mrcp_resource_header_property_check(
            request,
            ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_START_INPUT_TIMERS as usize,
        ) == ffi::TRUE
        {
            recog_channel.timers_started = (*recog_header).start_input_timers;
        }
        if mrcp_resource_header_property_check(
            request,
            ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_NO_INPUT_TIMEOUT as usize,
        ) == ffi::TRUE
        {
            ffi::mpf_activity_detector_noinput_timeout_set(
                recog_channel.detector.unwrap(),
                (*recog_header).no_input_timeout,
            );
        }
        if mrcp_resource_header_property_check(
            request,
            ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SPEECH_COMPLETE_TIMEOUT as usize,
        ) == ffi::TRUE
        {
            ffi::mpf_activity_detector_silence_timeout_set(
                recog_channel.detector.unwrap(),
                (*recog_header).speech_complete_timeout,
            );
        }
    }

    (*response).start_line.request_state = ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
    mrcp_engine_channel_message_send(channel, response);
    recog_channel.recog_request = Some(request);
    ffi::TRUE
}

// #[derive(Serialize)]
// struct Response {
//     result: RecognizerResult,
// }

// #[derive(Serialize)]
// struct RecognizerResult {
//     interpretation: Interpretation,
// }

// #[derive(Serialize)]
// struct Interpretation {
//     instance: String,
//     input: String,
// }
