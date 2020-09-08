use crate::{
    engine::{Config, Engine},
    error::Error,
    ffi,
    helper::*,
    pool::Pool,
    stem::{StreamingResponse, Summary},
    stream::STREAM_VTABLE,
};
use bytes::BytesMut;
use itertools::Itertools;
use serde::Deserialize;
use std::{
    ffi::{CStr, CString},
    ptr::NonNull,
    sync::Arc,
};
use tokio::sync::mpsc;
use xml::writer::XmlEvent;

#[repr(C)]
pub struct Channel {
    engine: *mut Engine,
    pub channel: NonNull<ffi::mrcp_engine_channel_t>,
    pub recog_request: Option<*mut ffi::mrcp_message_t>,
    pub stop_response: Option<*mut ffi::mrcp_message_t>,
    pub timers_started: ffi::apt_bool_t,
    pub detector: Option<*mut ffi::mpf_activity_detector_t>,
    sink: Option<mpsc::Sender<tungstenite::Message>>,
    results: Vec<StreamingResponse>,
    pub buffer: BytesMut,
    chunk_size: usize,
    completion_cause: Option<ffi::mrcp_recog_completion_cause_e::Type>,
    runtime_handle: tokio::runtime::Handle,
    config: Arc<Config>,
}

pub struct Message {
    pub channel: NonNull<ffi::mrcp_engine_channel_t>,
    message_type: MessageType,
}

#[derive(Debug)]
enum MessageType {
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

impl Channel {
    pub(crate) fn alloc(
        engine: *mut ffi::mrcp_engine_t,
        pool: &mut Pool,
    ) -> Result<NonNull<ffi::mrcp_engine_channel_t>, Error> {
        info!("Constructing a Deepgram ASR Engine Channel.");

        // TODO: This is really clunky, because we're mixing `*mut
        // ffi::mrcp_engine_t` and `*mut Engine`, and so they need to
        // be named differently.
        let engine_obj: &Engine = unsafe { &*((*engine).obj as *const _) };
        let config = engine_obj.config.clone();

        let data = Self {
            engine: unsafe { *engine }.obj as *mut _,
            recog_request: None,
            stop_response: None,
            detector: Some(unsafe { ffi::mpf_activity_detector_create(pool.get()) }),
            timers_started: ffi::FALSE,
            // This will be set before the end of this function.
            channel: NonNull::dangling(),
            sink: None,
            results: Vec::new(),
            buffer: BytesMut::new(),
            chunk_size: config.chunk_size as usize,
            completion_cause: None,
            runtime_handle: engine_obj.runtime_handle.clone(),
            config,
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

        let channel = match NonNull::new(unsafe {
            ffi::mrcp_engine_channel_create(
                engine,
                &CHANNEL_VTABLE,
                data as *mut _,
                termination,
                pool.get(),
            )
        }) {
            Some(ptr) => ptr,
            None => return Err(Error::Initialization),
        };

        unsafe {
            (*data).channel = channel;
        }

        Ok(channel)
    }

    // TODO: Since this is called from the task thread, it's possible
    // that it could create a race condition with the stream
    // thread. Therefore, we might not want to take `self` as a
    // mutable reference.
    pub fn process_message(&mut self, msg: Message) {
        match msg.message_type {
            MessageType::Open {
                rx,
                sample_rate,
                channels,
            } => {
                let auth = format!(
                    "{}:{}",
                    self.config.brain_username, self.config.brain_password
                );

                let mut url = self.config.brain_url.join("listen/stream").unwrap();
                // TODO: Perhaps these should not be hardcoded?
                url.query_pairs_mut()
                    .append_pair("endpointing", "true")
                    .append_pair("interim_results", "true")
                    .append_pair("encoding", "linear16")
                    .append_pair("sample_rate", &sample_rate.to_string())
                    .append_pair("channels", &channels.to_string());

                info!("Building request to {}", url);

                let req = http::Request::builder()
                    .uri(url.as_str())
                    .header("Authorization", format!("Basic {}", base64::encode(auth)))
                    .body(())
                    .unwrap();

                // TODO: This feels wrong.
                #[derive(Clone, Copy)]
                struct SendPtr<T>(*mut T);
                unsafe impl<T> Send for SendPtr<T> {}

                let channel = SendPtr(msg.channel.as_ptr());

                self.runtime_handle.spawn(async move {
                    info!("Opening websocket connection");
                    let result = match tokio_tungstenite::connect_async(req).await {
                        Ok((socket, response)) => {
                            use futures::prelude::*;
                            info!("Opened websocket connection :: {:?}", response);

                            tokio::spawn(async move {
                                let (mut ws_tx, mut ws_rx) = socket.split();
                                let mut rx = rx;
                                let write = async {
                                    info!("Begin writing to websocket");

                                    while let Some(msg) = rx.next().await {
                                        if let Err(err) = ws_tx.send(msg).await {
                                            warn!("Websocket connection closed: {}", err);
                                        }
                                    }

                                    let end = tungstenite::Message::Binary(vec![]);
                                    if let Err(err) = ws_tx.send(end).await {
                                        warn!("Websocket connection closed: {}", err);
                                    }

                                    info!("Done writing to websocket");
                                };
                                let read = async move {
                                    while let Some(msg) = ws_rx.next().await {
                                        trace!("received ws msg: {:?}", msg);

                                        let msg = match msg {
                                            Ok(msg) => msg,
                                            Err(tungstenite::Error::ConnectionClosed) => break,
                                            Err(err) => {
                                                warn!("WebSocket error: {}", err);
                                                continue;
                                            }
                                        };

                                        #[derive(Deserialize)]
                                        #[serde(untagged)]
                                        enum Message {
                                            Results(crate::stem::StreamingResponse),
                                            Summary(crate::stem::Summary),
                                        }

                                        match msg {
                                            tungstenite::Message::Close(_) => {
                                                info!("Websocket is closing");
                                                break;
                                            }
                                            tungstenite::Message::Text(buf) => {
                                                let msg: Message =
                                                    match serde_json::from_str(&buf) {
                                                        Ok(msg) => msg,
                                                        Err(err) => {
                                                            warn!("Failed to deserialize streaming response: {}", err);
                                                            debug!("{}", buf);
                                                            continue;
                                                        }
                                                    };

                                                let channel = unsafe { &mut *((*channel.0).method_obj as *mut Channel) };
                                                match msg {
                                                    Message::Results(msg) => channel.results_available(msg),
                                                    Message::Summary(msg) => channel.results_summary(msg),
                                                }
                                            }
                                            _ => warn!("Unhandled WS message type"),
                                        }
                                    }
                                };

                                future::join(write, read).await;
                                drop(ws_tx);
                            });

                            true
                        }
                        Err(err) => {
                            error!("Failed to open websocket connection: {}", err);
                            false
                        }
                    };
                });
            }
            MessageType::Close => unsafe {
                mrcp_engine_channel_close_respond(msg.channel.as_ptr());
            },
            MessageType::RequestProcess { request } => {
                let mut channel = msg.channel;

                let method_id = unsafe { request.as_ref().start_line.method_id as u32 };

                // TODO: Consider using ptr::NonNull here.
                let response =
                    unsafe { ffi::mrcp_response_create(request.as_ptr(), request.as_ref().pool) };
                let processed = match method_id {
                    ffi::mrcp_recognizer_method_id::RECOGNIZER_RECOGNIZE => unsafe {
                        crate::channel::recognize_channel(
                            channel.as_mut(),
                            request.as_ptr(),
                            response,
                        ) != 0
                    },
                    ffi::mrcp_recognizer_method_id::RECOGNIZER_START_INPUT_TIMERS => {
                        {
                            let channel =
                                unsafe { &mut *(channel.as_ref().method_obj as *mut Channel) };
                            channel.timers_started = ffi::TRUE;
                        }
                        unsafe { mrcp_engine_channel_message_send(channel.as_ptr(), response) != 0 }
                    }
                    ffi::mrcp_recognizer_method_id::RECOGNIZER_STOP => {
                        info!("Received STOP message");
                        let channel =
                            unsafe { &mut *(channel.as_ref().method_obj as *mut Channel) };
                        channel.stop_response = Some(response);
                        false
                    }
                    // TODO: These are probably useful to implement.
                    ffi::mrcp_recognizer_method_id::RECOGNIZER_SET_PARAMS => false,
                    ffi::mrcp_recognizer_method_id::RECOGNIZER_GET_PARAMS => false,
                    _ => false,
                };

                if !processed {
                    unsafe {
                        mrcp_engine_channel_message_send(channel.as_ptr(), response);
                    }
                }
            }
        }
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
            return false;
        }

        unsafe {
            (*message).start_line.request_state =
                ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
            mrcp_engine_channel_message_send(self.channel.as_ptr(), message) != 0
        }
    }

    pub fn results_available(&mut self, response: StreamingResponse) {
        if response.is_final {
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
        }

        if response.is_final {
            self.results.push(response);

            if self.config.stream_results {
                let cause = ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS;
                match self.send_recognition_complete(cause) {
                    Ok(()) => self.results.clear(),
                    Err(()) => error!("Failed to send results"),
                }
            }
        }
    }

    fn build_response(&self, plaintext_results: bool) -> xml::writer::Result<CString> {
        let transcript = self
            .results
            .iter()
            .filter_map(|resp| resp.channel.alternatives.get(0))
            .map(|alt| alt.transcript.as_str())
            .filter(|alt| !alt.is_empty())
            .join(" ");

        // Take the median of the confidence values.
        let confidence = {
            let mut confidences: Vec<_> = self
                .results
                .iter()
                .filter_map(|resp| resp.channel.alternatives.get(0))
                .map(|alt| alt.confidence)
                .collect();
            confidences.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
            match confidences.len() {
                0 => 0.0,
                n if n % 2 == 0 => 0.5 * (confidences[n / 2 - 1] + confidences[n / 2]),
                n => confidences[n / 2],
            }
        };

        // Short circuit for the case where we want to return
        // plaintext results instead of an XML response. This is
        // contrary to the MRCP spec, but it can be useful for
        // debugging.
        if plaintext_results {
            return Ok(CString::new(transcript).unwrap());
        }

        let mut buffer = vec![];
        let mut writer = xml::EmitterConfig::new()
            .perform_indent(true)
            .create_writer(&mut buffer);
        writer.write(XmlEvent::start_element("result"))?;
        writer.write(
            XmlEvent::start_element("interpretation")
                .attr("grammar", "session:request1@form-level.store")
                .attr("confidence", &confidence.to_string()),
        )?;
        writer.write(XmlEvent::start_element("instance"))?;
        writer.write(XmlEvent::characters(transcript.as_str()))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::start_element("input").attr("mode", "speech"))?;
        writer.write(XmlEvent::characters(transcript.as_str()))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(CString::new(buffer).unwrap())
    }

    pub fn results_summary(&mut self, summary: Summary) {
        info!("results_summary({:?})", summary);

        if self.recog_request.is_none() {
            return;
        }

        let cause = ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS;
        match self.send_recognition_complete(cause) {
            Ok(()) => (),
            Err(()) => error!("failed to send recognition results"),
        }

        self.recog_request.take();
    }

    pub fn end_of_input(&mut self, cause: ffi::mrcp_recog_completion_cause_e::Type) {
        debug!("end_of_input");

        if self.sink.take().is_some() {
            info!("closed write end of channel");
        }
        self.completion_cause = Some(cause);
    }

    pub fn send_recognition_complete(
        &mut self,
        cause: ffi::mrcp_recog_completion_cause_e::Type,
    ) -> Result<(), ()> {
        debug!("send recognition complete");

        let message = unsafe {
            ffi::mrcp_event_create(
                self.recog_request.unwrap() as *const _,
                ffi::mrcp_recognizer_event_id::RECOGNIZER_RECOGNITION_COMPLETE as usize,
                (*self.recog_request.unwrap()).pool,
            )
        };

        if message.is_null() {
            return Err(());
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
            let plaintext_results = self.config.plaintext_results;

            let body = match self.build_response(plaintext_results) {
                Ok(body) => body,
                Err(err) => {
                    warn!("Failed to build response body: {}", err);
                    // TODO: This leaks memory from the allocation of
                    // the message above.
                    return Err(());
                }
            };

            unsafe {
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

        unsafe {
            mrcp_engine_channel_message_send(self.channel.as_ptr(), message) != 0;
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), ()> {
        while self.buffer.len() >= self.chunk_size {
            let sink = match self.sink.as_mut() {
                Some(sink) => sink,
                None => {
                    warn!("no websocket sink");
                    return Err(());
                }
            };
            let message = tungstenite::Message::binary(self.buffer.split().as_ref());
            if let Err(err) = self.runtime_handle.block_on(sink.send(message)) {
                error!("failed to send buffer: {}", err);
                return Err(());
            }
        }

        Ok(())
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
    mrcp_engine_channel_open_respond(channel, ffi::TRUE)
}

unsafe extern "C" fn channel_close(channel: *mut ffi::mrcp_engine_channel_t) -> ffi::apt_bool_t {
    debug!("Closing Deepgram ASR channel.");

    let mut channel = NonNull::new(channel).expect("channel ptr should never be null");
    let channel_data = &mut *(channel.as_mut().method_obj as *mut Channel);
    channel_data.sink.take();

    msg_signal(MessageType::Close, channel)
}

unsafe extern "C" fn channel_process_request(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    let channel = NonNull::new(channel).expect("channel ptr should never be null");
    let request = NonNull::new(request).expect("request pointer should never be null");
    msg_signal(MessageType::RequestProcess { request }, channel)
}

unsafe fn msg_signal(
    message_type: MessageType,
    channel: NonNull<ffi::mrcp_engine_channel_t>,
) -> ffi::apt_bool_t {
    debug!("Message signal: {:?}", message_type);
    let channel_data = &mut *(channel.as_ref().method_obj as *mut Channel);
    let engine = channel_data.engine;
    let task = ffi::apt_consumer_task_base_get((*engine).task);
    let msg_ptr = ffi::apt_task_msg_get(task);
    if !msg_ptr.is_null() {
        let msg = &mut (*msg_ptr).data as *mut _ as *mut Message;
        std::ptr::write(
            msg,
            Message {
                message_type,
                channel,
            },
        );

        ffi::apt_task_msg_signal(task, msg_ptr)
    } else {
        ffi::FALSE
    }
}

pub(crate) unsafe fn recognize_channel(
    channel: &mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
    response: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    debug!("Channel recognize.");
    let recog_channel = &mut *(channel.method_obj as *mut Channel);
    let descriptor = ffi::mrcp_engine_sink_stream_codec_get(channel as *mut _);

    if descriptor.is_null() {
        warn!("Failed to get codec description.");
        (*response).start_line.status_code =
            ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;
        return ffi::FALSE;
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

    recog_channel.results.clear();

    let (tx, rx) = mpsc::channel(8);
    recog_channel.sink = Some(tx);
    let codec_descriptor = ffi::mrcp_engine_sink_stream_codec_get(channel as *mut _);
    if codec_descriptor.is_null() {
        error!("Failed to get codec descriptor");
        return ffi::FALSE;
    }
    msg_signal(
        MessageType::Open {
            rx,
            sample_rate: (*codec_descriptor).sampling_rate,
            channels: (*codec_descriptor).channel_count,
        },
        channel.into(),
    );

    (*response).start_line.request_state = ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
    recog_channel.recog_request = Some(request);

    mrcp_engine_channel_message_send(channel, response)
}
