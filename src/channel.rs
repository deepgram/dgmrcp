use crate::{
    engine::Config,
    ffi,
    helper::*,
    stem::{StreamingResponse, Summary},
};
use bytes::BytesMut;
use futures::prelude::*;
use itertools::Itertools;
use serde::Deserialize;
use std::{
    ffi::{CStr, CString},
    ptr::NonNull,
    sync::Arc,
};
use tokio::sync::mpsc;
use xml::writer::XmlEvent;

mod send_ptr {
    /// Wrap a pointer so that it implements `Send`. This is unsafe.
    pub struct SendPtr<T>(*mut T);

    unsafe impl<T> Send for SendPtr<T> {}

    impl<T> SendPtr<T> {
        /// Contsruct a pointer wrapper that is `Send`.
        pub fn new(ptr: *mut T) -> SendPtr<T> {
            SendPtr(ptr)
        }

        /// Get the enclosed pointer.
        pub unsafe fn get(&self) -> *mut T {
            self.0
        }
    }
}
use send_ptr::SendPtr;

#[repr(C)]
pub struct Channel {
    pub channel: NonNull<ffi::mrcp_engine_channel_t>,
    pub recog_request: Option<*mut ffi::mrcp_message_t>,
    pub stop_response: Option<*mut ffi::mrcp_message_t>,
    pub timers_started: ffi::apt_bool_t,
    pub detector: Vad,
    sink: Option<mpsc::Sender<tungstenite::Message>>,
    results: Vec<StreamingResponse>,
    pub buffer: BytesMut,
    chunk_size: usize,
    completion_cause: Option<ffi::mrcp_recog_completion_cause_e::Type>,
    runtime_handle: tokio::runtime::Handle,
    config: Arc<Config>,
    parameters: Parameters,
}

pub enum Vad {
    UniMrcp(NonNull<ffi::mpf_activity_detector_t>),
    Dg { speaking: bool },
}

#[derive(Default)]
struct Parameters {
    language: Option<String>,
}

impl Channel {
    /// Define the channel v-table
    pub const VTABLE: ffi::mrcp_engine_channel_method_vtable_t =
        ffi::mrcp_engine_channel_method_vtable_t {
            destroy: Some(channel_destroy),
            open: Some(channel_open),
            close: Some(channel_close),
            process_request: Some(channel_process_request),
        };

    pub fn new(
        pool: *mut ffi::apr_pool_t,
        config: Arc<Config>,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        info!("Constructing a Deepgram ASR Engine Channel.");

        let detector = if config.dg_vad {
            Vad::Dg { speaking: false }
        } else {
            unsafe {
                let detector = ffi::mpf_activity_detector_create(pool);
                ffi::mpf_activity_detector_level_set(detector, 8);
                Vad::UniMrcp(NonNull::new_unchecked(detector))
            }
        };

        Channel {
            recog_request: None,
            stop_response: None,
            detector,
            timers_started: ffi::FALSE,
            // This will be set before the end of this function.
            channel: NonNull::dangling(),
            sink: None,
            results: Vec::new(),
            buffer: BytesMut::new(),
            chunk_size: config.chunk_size as usize,
            completion_cause: None,
            runtime_handle,
            config,
            parameters: Default::default(),
        }
    }

    pub fn process_request(&mut self, request: NonNull<ffi::mrcp_message_t>) {
        let method_id = unsafe { request.as_ref().start_line.method_id as u32 };

        // TODO: Consider using ptr::NonNull here.
        let response =
            unsafe { ffi::mrcp_response_create(request.as_ptr(), request.as_ref().pool) };
        let processed = match method_id {
            ffi::mrcp_recognizer_method_id::RECOGNIZER_RECOGNIZE => unsafe {
                recognize_channel(self.channel.as_mut(), request.as_ptr(), response) != 0
            },
            ffi::mrcp_recognizer_method_id::RECOGNIZER_START_INPUT_TIMERS => {
                self.timers_started = ffi::TRUE;
                unsafe { mrcp_engine_channel_message_send(self.channel.as_ptr(), response) != 0 }
            }
            ffi::mrcp_recognizer_method_id::RECOGNIZER_STOP => {
                info!("Received STOP message");
                self.stop_response = Some(response);
                false
            }
            // TODO: These are probably useful to implement.
            ffi::mrcp_recognizer_method_id::RECOGNIZER_SET_PARAMS => {
                self.set_params(request.as_ptr());
                false
            }
            ffi::mrcp_recognizer_method_id::RECOGNIZER_GET_PARAMS => false,
            _ => false,
        };

        if !processed {
            unsafe {
                mrcp_engine_channel_message_send(self.channel.as_ptr(), response);
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

        match self.detector {
            Vad::Dg { ref mut speaking } => {
                if !*speaking
                    && response
                        .channel
                        .alternatives
                        .get(0)
                        .map(|alt| !alt.transcript.is_empty())
                        .unwrap_or(false)
                {
                    info!("speaking {} => true", speaking);
                    *speaking = true;
                    self.start_of_input();
                } else if *speaking && response.speech_final {
                    info!("speaking {} => false", speaking);
                    *speaking = false;
                    self.end_of_input(
                        ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS,
                    );
                }
            }
            _ => (),
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

            // Although this blocks on an async call, it should
            // normally return very quickly. The only reason why it
            // would block for a measurable length of time is if the
            // mpsc channel is full. In that case, the UniMRCP stream
            // callback will block.
            //
            // TODO: If we don't want to allow for blocked packets,
            // thin it shouldn't really matter where we block. If we
            // do want to allow for dropped packets, then which is the
            // better place to handle that? If we don't want dropped
            // packets, but we also don't want to block here, then we
            // should switch to an unbounded channel so that we we can
            // enqueue messages from this thread, ensuring they are
            // placed in the correct order.
            if let Err(err) = self.runtime_handle.block_on(sink.send(message)) {
                error!("failed to send buffer: {}", err);
                return Err(());
            }
        }

        Ok(())
    }

    fn set_params(&mut self, request: *mut ffi::mrcp_message_t) -> Result<(), ()> {
        let headers = NonNull::new(
            unsafe { mrcp_resource_header_get(request) } as *mut ffi::mrcp_recog_header_t
        )
        .ok_or(())?;

        if unsafe {
            mrcp_resource_header_property_check(
                request,
                ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SPEECH_LANGUAGE,
            )
        } == ffi::TRUE
        {
            let language = unsafe { headers.as_ref() }.speech_language.as_str();
            self.parameters.language = Some(language.to_string());
        }

        Ok(())
    }
}

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

    let channel = SendPtr::new(channel.as_ptr());

    channel_data.runtime_handle.spawn_blocking(move || {
        // This is safe because UniMRCP will not deallocate the
        // channel until after the close response has been sent.
        let channel = channel.get();
        mrcp_engine_channel_close_respond(channel);
    });

    ffi::TRUE
}

unsafe extern "C" fn channel_process_request(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    let channel_data_ptr = SendPtr::new((*channel).method_obj as *mut Channel);
    let request = SendPtr::new(request);

    (*channel_data_ptr.get())
        .runtime_handle
        .spawn_blocking(move || {
            // TODO: This is not safe, because the channel may have been
            // deallocated before this cloure gets run.
            let channel_data = &mut *(channel_data_ptr.get());
            let request =
                NonNull::new(request.get()).expect("request pointer should never be null");

            channel_data.process_request(request);
        });

    ffi::TRUE
}

unsafe fn recognize_channel(
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

    let mut recognize_language = None;

    let recog_header = mrcp_resource_header_get(request) as *mut ffi::mrcp_recog_header_t;
    if !recog_header.is_null() {
        if mrcp_resource_header_property_check(
            request,
            ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_START_INPUT_TIMERS,
        ) == ffi::TRUE
        {
            recog_channel.timers_started = (*recog_header).start_input_timers;
        }
        if mrcp_resource_header_property_check(
            request,
            ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_NO_INPUT_TIMEOUT,
        ) == ffi::TRUE
        {
            if let Vad::UniMrcp(detector) = recog_channel.detector {
                ffi::mpf_activity_detector_noinput_timeout_set(
                    detector.as_ptr(),
                    (*recog_header).no_input_timeout,
                );
            }
        }
        if mrcp_resource_header_property_check(
            request,
            ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SPEECH_COMPLETE_TIMEOUT,
        ) == ffi::TRUE
        {
            if let Vad::UniMrcp(detector) = recog_channel.detector {
                ffi::mpf_activity_detector_silence_timeout_set(
                    detector.as_ptr(),
                    (*recog_header).speech_complete_timeout,
                );
            }
        }

        if mrcp_resource_header_property_check(
            request,
            ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SPEECH_LANGUAGE,
        ) == ffi::TRUE
        {
            recognize_language = Some((*recog_header).speech_language.as_str());
        }
    }

    recog_channel.results.clear();

    let (tx, rx) = mpsc::channel(1024);
    recog_channel.sink = Some(tx);
    let codec_descriptor = ffi::mrcp_engine_sink_stream_codec_get(channel as *mut _);
    if codec_descriptor.is_null() {
        error!("Failed to get codec descriptor");
        return ffi::FALSE;
    }

    recog_channel.runtime_handle.spawn({
        let config = recog_channel.config.clone();
        let channel = SendPtr::new(channel);
        let sample_rate = (*codec_descriptor).sampling_rate;
        let channels = (*codec_descriptor).channel_count;
        let model = recog_channel.config.model.clone();
        // Use the most specific configured language, if
        // available.
        let language = recognize_language
            .or(recog_channel.parameters.language.as_deref())
            .or(recog_channel.config.language.as_deref())
            .map(|s| s.to_string());
        run_request(config, channel, rx, sample_rate, channels, model, language)
    });

    (*response).start_line.request_state = ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
    recog_channel.recog_request = Some(request);

    mrcp_engine_channel_message_send(channel, response)
}

async fn run_request(
    config: Arc<Config>,
    channel: SendPtr<ffi::mrcp_engine_channel_t>,
    mut rx: mpsc::Receiver<tungstenite::Message>,
    sample_rate: u16,
    channels: u8,
    model: Option<String>,
    language: Option<String>,
) {
    let auth = format!("{}:{}", config.brain_username, config.brain_password);

    let mut url = config.brain_url.join("listen/stream").unwrap();
    // TODO: Perhaps these should not be hardcoded?
    url.query_pairs_mut()
        .append_pair("endpointing", "true")
        // TODO: The default value is 60 ms, but it's easier to test
        // things with a large buffer. This should be configurable
        // anyway.
        .append_pair("vad_turnoff", "1000")
        .append_pair("interim_results", "true")
        .append_pair("encoding", "linear16")
        .append_pair("sample_rate", &sample_rate.to_string())
        .append_pair("channels", &channels.to_string());
    if let Some(model) = model {
        url.query_pairs_mut().append_pair("model", &model);
    }
    if let Some(language) = language {
        url.query_pairs_mut().append_pair("language", &language);
    }

    info!("Building request to {}", url);

    let req = http::Request::builder()
        .uri(url.as_str())
        .header("Authorization", format!("Basic {}", base64::encode(auth)))
        .body(())
        .unwrap();

    info!("Opening websocket connection");
    let (socket, response) = match tokio_tungstenite::connect_async(req).await {
        Err(err) => {
            error!("Failed to open websocket connection: {}", err);
            // TODO: Send a response to this error.
            return;
        }
        Ok(pair) => pair,
    };
    info!("Opened websocket connection :: {:?}", response);

    let (mut ws_tx, mut ws_rx) = socket.split();
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

        drop(ws_tx);
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
                    let msg: Message = match serde_json::from_str(&buf) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!("Failed to deserialize streaming response: {}", err);
                            debug!("{}", buf);
                            continue;
                        }
                    };

                    let channel = unsafe { &mut *((*channel.get()).method_obj as *mut Channel) };
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

    info!("request complete");
}
