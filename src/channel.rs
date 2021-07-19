use crate::{
    engine::Config,
    ffi,
    helper::*,
    stem::{StreamingResponse, Summary},
};
use async_tungstenite::tungstenite;
use bytes::BytesMut;
use futures::prelude::*;
use itertools::Itertools;
use serde::Deserialize;
use std::{
    ffi::{CStr, CString},
    ptr::NonNull,
    sync::{Arc, Mutex},
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
    runtime: Arc<tokio::runtime::Runtime>,
    config: Arc<Config>,
    request_grammars: Vec<String>,
}

/// This is safe, because we promise to always access `Channel` via an
/// `Arc<Mutex<Channel>>`. On its own, `Channel` should not be safe
/// because it contains raw pointers.
unsafe impl Send for Channel {}

pub struct Vad {
    /// Set to true when the backend starts to return ASR results that
    /// contain words. Whereas the activity detector can be triggered
    /// by background noise, this can be taken as an indicator that
    /// speech has started with a very low chance of false positives.
    ///
    /// Once this has become true, we can ignore the activity detector
    /// from that point on.
    pub speaking: bool,

    /// The activity detector can trigger on background noise, but it
    /// is much more responsive than waiting for ASR results since it
    /// doesn't incur the cost of network latency and backend
    /// processing time.
    pub activity_detector: Option<NonNull<ffi::mpf_activity_detector_t>>,
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

    // NOTE: This is a reasonable default that seems to work well with
    // my phone. It will most likely have to be adjusted.
    const DEFAULT_SENSITIVITY_LEVEL: f32 = 0.0625;

    pub fn new(
        pool: *mut ffi::apr_pool_t,
        config: Arc<Config>,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Arc<Mutex<Self>> {
        info!("Constructing a Deepgram ASR Engine Channel.");

        let detector = unsafe {
            let detector = ffi::mpf_activity_detector_create(pool);
            Vad {
                speaking: false,
                activity_detector: NonNull::new(detector),
            }
        };

        let channel = Channel {
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
            runtime,
            config,
            request_grammars: vec![],
        };

        Arc::new(Mutex::new(channel))
    }

    /// Process an MRCP request. This is called from
    /// `channel_process_request` and is run on the tokio threadpool,
    /// using `spawn_blocking`. Therefore, it is okay to block in this
    /// function.
    ///
    /// # Not handling SET-PARAMS and GET-PARAMS
    ///
    /// We explicitly don't handle the SET-PARAMS message, because it
    /// is already handled by UniMRCP. If a SET-PARAMS message has
    /// previously been received on this channel, then UniMRCP will
    /// save its header and merge them in to a subsequent RECOGNIZE
    /// message. This allows the plugin to assume that all parameters
    /// will be present in a RECOGNIZE message without dealing with
    /// the statefulness of SET-PARAMS. See
    /// `recog_request_recognize()` and `mrcp_header_fields_inherit()`
    /// in the UniMRCP source for the implementation of this
    /// behaviour.
    ///
    /// It appears that UniMRCP does not implement the wildcard
    /// variant of GET-PARAMS.
    fn process_request(&mut self, request: NonNull<ffi::mrcp_message_t>) {
        let method_id = unsafe { request.as_ref().start_line.method_id as u32 };

        // TODO: Consider using ptr::NonNull here.
        let response =
            unsafe { ffi::mrcp_response_create(request.as_ptr(), request.as_ref().pool) };
        match method_id {
            ffi::mrcp_recognizer_method_id::RECOGNIZER_RECOGNIZE => {
                self.recognize(request.as_ptr(), response);
            }
            ffi::mrcp_recognizer_method_id::RECOGNIZER_START_INPUT_TIMERS => {
                if let Some(detector) = self.detector.activity_detector {
                    unsafe {
                        ffi::mpf_activity_detector_reset(detector.as_ptr());
                    }
                }
                self.timers_started = ffi::TRUE;
            }
            ffi::mrcp_recognizer_method_id::RECOGNIZER_STOP => {
                info!("Received STOP message");
                self.stop_response = Some(response);
            }
            _ => (),
        }

        unsafe {
            mrcp_engine_channel_message_send(self.channel.as_ptr(), response);
        }
    }

    fn recognize(&mut self, request: *mut ffi::mrcp_message_t, response: *mut ffi::mrcp_message_t) {
        info!("Channel::recognize");

        // Clear the results from a previous RECOGNIZE request.
        self.results.clear();
        self.request_grammars.clear();

        let response = unsafe { &mut *response };

        let descriptor = unsafe { ffi::mrcp_engine_sink_stream_codec_get(self.channel.as_ptr()) };
        if descriptor.is_null() {
            warn!("Failed to get codec description.");
            response.start_line.status_code =
                ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;
            return;
        }

        self.timers_started = ffi::FALSE;
        self.detector.speaking = false;
        if let Some(detector) = self.detector.activity_detector {
            unsafe {
                ffi::mpf_activity_detector_reset(detector.as_ptr());
            }
        }

        #[derive(Debug, Default, Deserialize)]
        struct VendorHeaders {
            #[serde(rename = "com.deepgram.model")]
            model: Option<String>,

            #[serde(rename = "com.deepgram.numerals")]
            numerals: Option<bool>,

            #[serde(rename = "com.deepgram.ner")]
            ner: Option<bool>,

            #[serde(rename = "com.deepgram.no_delay")]
            no_delay: Option<bool>,

            #[serde(rename = "com.deepgram.plugin")]
            plugin: Option<String>,

            #[serde(rename = "com.deepgram.keywords")]
            keywords: Option<String>,
        }

        let vendor_headers: VendorHeaders = if unsafe {
            mrcp_generic_header_property_check(
                request,
                ffi::mrcp_generic_header_id::GENERIC_HEADER_VENDOR_SPECIFIC_PARAMS,
            )
        } {
            let generic_headers = unsafe { mrcp_generic_header_get(request) };
            match crate::vendor_params::from_header_array(unsafe {
                (*generic_headers).vendor_specific_params
            }) {
                Ok(headers) => headers,
                Err(err) => {
                    error!("Failed to deserialize headers: {}", err);
                    response.start_line.status_code =
                        ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;
                    return;
                }
            }
        } else {
            Default::default()
        };

        let headers = unsafe { mrcp_resource_header_get(request) as *mut ffi::mrcp_recog_header_t };
        if headers.is_null() {
            warn!("Failed to get headers");
            response.start_line.status_code =
                ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;
            return;
        }

        if unsafe {
            mrcp_resource_header_property_check(
                request,
                ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_START_INPUT_TIMERS,
            )
        } {
            self.timers_started = unsafe { (*headers).start_input_timers };
        }

        if unsafe {
            mrcp_resource_header_property_check(
                request,
                ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_NO_INPUT_TIMEOUT,
            )
        } {
            if let Some(detector) = self.detector.activity_detector {
                unsafe {
                    ffi::mpf_activity_detector_noinput_timeout_set(
                        detector.as_ptr(),
                        (*headers).no_input_timeout,
                    );
                }
            }
        }

        if unsafe {
            mrcp_resource_header_property_check(
                request,
                ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SPEECH_COMPLETE_TIMEOUT,
            )
        } {
            if let Some(detector) = self.detector.activity_detector {
                unsafe {
                    ffi::mpf_activity_detector_silence_timeout_set(
                        detector.as_ptr(),
                        (*headers).speech_complete_timeout,
                    );
                }
            }
        }

        let header_sensitivity = if unsafe {
            mrcp_resource_header_property_check(
                request,
                ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SENSITIVITY_LEVEL,
            )
        } {
            unsafe { Some((*headers).sensitivity_level) }
        } else {
            None
        };

        let sensitivity = header_sensitivity
            .or(self.config.sensitivity_level)
            .unwrap_or(Channel::DEFAULT_SENSITIVITY_LEVEL);

        if let Some(detector) = self.detector.activity_detector {
            unsafe {
                // Invert and scale to [0, 255]; that is, 0.0 -> 255 and 1.0 -> 0
                let sensitivity = sensitivity.max(0.0).min(1.0);
                let level = 255 - (sensitivity * 255.0) as usize;
                ffi::mpf_activity_detector_level_set(detector.as_ptr(), level);
            }
        }

        let recognize_language = if unsafe {
            mrcp_resource_header_property_check(
                request,
                ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_SPEECH_LANGUAGE,
            )
        } {
            unsafe { Some((*headers).speech_language.as_str()) }
        } else {
            None
        };

        // Determine whether the body contains a grammar.

        if unsafe {
            mrcp_generic_header_property_check(
                request,
                ffi::mrcp_generic_header_id::GENERIC_HEADER_CONTENT_TYPE,
            )
        } {
            let generic_headers = unsafe { mrcp_generic_header_get(request) };
            match unsafe { (*generic_headers).content_type.as_str() } {
                "text/uri-list" => {
                    self.request_grammars = unsafe { (*request).body.as_str() }
                        .lines()
                        .map(|s| s.to_string())
                        .collect();
                }

                // Other valid `content-type`values include
                // "text/grammar-ref-list" and "application/srgs+xml",
                // but we are not currently handling them.
                content_type => {
                    error!(
                        "RECOGNIZE content-type header not supported: {}",
                        content_type
                    );
                    // Unsupported Header Field Value. See
                    // https://tools.ietf.org/html/rfc6787#section-5.4
                    response.start_line.status_code = 409;
                    unsafe {
                        let header = mrcp_generic_header_prepare(response);
                        apt_string_assign_n(
                            &mut (*header).content_type,
                            content_type.as_ptr() as *const i8,
                            content_type.len(),
                            (*response).pool,
                        );
                        ffi::mrcp_generic_header_property_add(
                            response,
                            ffi::mrcp_generic_header_id::GENERIC_HEADER_CONTENT_TYPE as usize,
                        );
                    }
                    return;
                }
            }
        }

        let (tx, mut rx) = mpsc::channel(1024);
        self.sink = Some(tx);
        let codec_descriptor =
            unsafe { ffi::mrcp_engine_sink_stream_codec_get(self.channel.as_ptr()) };
        if codec_descriptor.is_null() {
            error!("Failed to get codec descriptor");
            response.start_line.status_code =
                ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;
            return;
        }

        // Build the request

        let auth = match (&self.config.brain_username, &self.config.brain_password) {
            (Some(username), Some(password)) => Some(format!("{}:{}", username, password)),
            _ => None,
        };
        let mut url = self.config.brain_url.join("listen/stream").unwrap();
        // TODO: Perhaps these should not be hardcoded?
        url.query_pairs_mut()
            .append_pair("endpointing", "true")
            // TODO: The default value is 60 ms, but it's easier to
            // test things with a large buffer. This should be
            // configurable anyway.
            .append_pair("vad_turnoff", "300")
            .append_pair("interim_results", "true")
            .append_pair("encoding", "linear16")
            .append_pair("sample_rate", unsafe {
                &(*codec_descriptor).sampling_rate.to_string()
            })
            .append_pair("channels", unsafe {
                &(*codec_descriptor).channel_count.to_string()
            });
        if let Some(model) = vendor_headers.model.or_else(|| self.config.model.clone()) {
            url.query_pairs_mut().append_pair("model", &model);
        }
        if let Some(language) = recognize_language.or(self.config.language.as_deref()) {
            url.query_pairs_mut().append_pair("language", language);
        }
        if let Some(numerals) = vendor_headers.numerals.or(self.config.numerals) {
            url.query_pairs_mut()
                .append_pair("numerals", if numerals { "true" } else { "false" });
        }
        if let Some(ner) = vendor_headers.ner.or(self.config.ner) {
            url.query_pairs_mut()
                .append_pair("ner", if ner { "true" } else { "false" });
        }
        if let Some(no_delay) = vendor_headers.no_delay.or(self.config.no_delay) {
            url.query_pairs_mut()
                .append_pair("no_delay", if no_delay { "true" } else { "false" });
        }
        if let Some(keywords) = vendor_headers
            .keywords
            .as_deref()
            .or(self.config.keywords.as_deref())
        {
            for keyword in keywords.split(',') {
                url.query_pairs_mut().append_pair("keywords", keyword);
            }
        }
        if let Some(plugins) = vendor_headers
            .plugin
            .as_deref()
            .or(self.config.plugin.as_deref())
        {
            // We split on the comma here because it's easier than
            // implementing it in the deserializer. It would be worth
            // implementaing there if we want to support more
            // multi-valued query params.
            for plugin in plugins.split(',') {
                url.query_pairs_mut().append_pair("plugin", plugin);
            }
        }

        info!("Building request to {}", url);

        let mut req = http::Request::builder().uri(url.as_str());
        if let Some(auth) = auth {
            req = req.header("Authorization", format!("Basic {}", base64::encode(auth)))
        }
        let req = req.body(()).unwrap();

        info!("Opening websocket connection");
        let (socket, _http_response) = match self
            .runtime
            .block_on(async_tungstenite::tokio::connect_async(req))
        {
            Ok(pair) => pair,
            Err(err) => {
                error!("Failed to open WebSocket connection: {}", err);
                // TODO: this is not the right response code.
                response.start_line.status_code =
                    ffi::mrcp_status_code_e::MRCP_STATUS_CODE_METHOD_FAILED;

                let header = unsafe {
                    mrcp_resource_header_prepare(response) as *mut ffi::mrcp_recog_header_t
                };
                unsafe {
                    (*header).completion_cause =
                        ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_ERROR;
                    ffi::mrcp_resource_header_property_add(
                        response,
                        ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_COMPLETION_CAUSE as usize,
                    );

                    let reason = match err {
                        tungstenite::Error::Http(http::StatusCode::UNAUTHORIZED) => CStr::from_bytes_with_nul_unchecked(b"Check that credentials are properly configured.\0"),
                        tungstenite::Error::Http(http::StatusCode::FORBIDDEN) => CStr::from_bytes_with_nul_unchecked(b"Check that the requested model is valid.\0"),
                        _ => CStr::from_bytes_with_nul_unchecked(b"Check that credentials are properly configured and the requested model is valid.\0")
                    };

                    apt_string_assign(
                        &mut (*header).completion_reason,
                        reason.as_ptr(),
                        (*response).pool,
                    );

                    ffi::mrcp_resource_header_property_add(
                        response,
                        ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_COMPLETION_REASON
                            as usize,
                    );
                }

                return;
            }
        };

        let (mut ws_tx, mut ws_rx) = socket.split();

        let write = async move {
            info!("Begin writing to websocket");

            while let Some(msg) = rx.recv().await {
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

        // This is a really weird self-referential expression. The
        // `ffi::mrcp_engine_channel_t` owns the `Channel` struct via
        // an `Arc<Mutex<Channel>>`, which is (in the scope of this
        // function) currently bound to `&mut self`. Since we're going
        // to spawn a task which may continue past the lifetime of the
        // channel, we need to ensure it doesn't invoke callbacks on
        // the channel after it has been destroyed.
        //
        // By casting `Channel::channel` to an `Arc`, we _do_ have
        // multiple mutable references to the `Arc` itself (one here
        // and one further up the call stack), but since we aren't
        // going to modify the `Arc`, this _should_ be safe.
        let channel = unsafe {
            let arc = &mut *(self.channel.as_ref().method_obj as *mut Arc<Mutex<Channel>>);
            Arc::downgrade(arc)
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

                        let channel = match channel.upgrade() {
                            None => {
                                // TODO: Should this really be an
                                // error? It is actually very normal
                                // to send `RECOGNITION-COMPLETE`,
                                // close the channel, and _then_
                                // receive few more results or a
                                // summary message from the backend.
                                error!("Channel has been deallocated");
                                return;
                            }
                            Some(ptr) => ptr,
                        };
                        let mut channel = channel.lock().unwrap();

                        match msg {
                            Message::Results(msg) => channel.results_available(msg),
                            Message::Summary(msg) => channel.results_summary(msg),
                        }
                    }
                    _ => warn!("Unhandled WS message type"),
                }
            }
        };

        self.runtime.spawn(future::join(write, read));

        info!("handled RECOGNIZE request");
        response.start_line.request_state =
            ffi::mrcp_request_state_e::MRCP_REQUEST_STATE_INPROGRESS;
        self.recog_request = Some(request);
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
                "Results available (IS_FINAL={} SPEECH_FINAL={}): {}",
                response.is_final,
                response.speech_final,
                response
                    .channel
                    .alternatives
                    .get(0)
                    .map(|alt| alt.transcript.as_str())
                    .unwrap_or("<< NO RESULTS >>")
            );
        }

        let contains_speech = response
            .channel
            .alternatives
            .get(0)
            .map(|alt| !alt.transcript.is_empty())
            .unwrap_or(false);

        if !self.detector.speaking && contains_speech {
            info!("speaking false => true");
            self.detector.speaking = true;
            self.start_of_input();
        } else if self.detector.speaking && response.speech_final {
            info!("speaking true => false");
            // TODO: This will still cause the recognizer to wait
            // until the remaining ASR results come back. At this
            // point, we've sent more audio to the backend than we
            // care about; we'll still need to wait until the WS
            // closes though.
            self.end_of_input(
                ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS,
            );
        }

        // Copy the boolean because we're about to pass ownership of
        // the result.
        let speech_final = response.speech_final;

        // TODO: Do we miss the last result because we called
        // end_of_input already?
        if response.is_final {
            self.results.push(response);

            if self.config.stream_results {
                match self.send_recognition_complete() {
                    Ok(()) => self.results.clear(),
                    Err(()) => error!("Failed to send results"),
                }
            }
        }

        if speech_final {
            match self.send_recognition_complete() {
                Ok(()) => self.results.clear(),
                Err(()) => error!("Failed to send results"),
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
        writer.write({
            let element = XmlEvent::start_element("interpretation");
            let element = match self.request_grammars.first() {
                Some(grammar) => element.attr("grammar", grammar),
                None => element,
            };
            element.attr("confidence", &confidence.to_string())
        })?;
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

        match self.send_recognition_complete() {
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

    pub fn send_recognition_complete(&mut self) -> Result<(), ()> {
        debug!("send recognition complete");

        // If there isn't an active request, then that means we've
        // already responded, and so we shouldn't respond a second
        // time.
        let recognize_request = self.recog_request.take().ok_or(())?;

        let cause = self
            .completion_cause
            .take()
            .unwrap_or(ffi::mrcp_recog_completion_cause_e::RECOGNIZER_COMPLETION_CAUSE_SUCCESS);

        let message = unsafe {
            ffi::mrcp_event_create(
                recognize_request as *const _,
                ffi::mrcp_recognizer_event_id::RECOGNIZER_RECOGNITION_COMPLETE as usize,
                (*recognize_request).pool,
            )
        };

        if message.is_null() {
            return Err(());
        }

        let header =
            unsafe { mrcp_resource_header_prepare(message) as *mut ffi::mrcp_recog_header_t };
        if header.is_null() {
            return Err(());
        }

        unsafe {
            (*header).completion_cause = cause;
            ffi::mrcp_resource_header_property_add(
                message,
                ffi::mrcp_recognizer_header_id::RECOGNIZER_HEADER_COMPLETION_CAUSE as usize,
            );
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

        if unsafe { mrcp_engine_channel_message_send(self.channel.as_ptr(), message) } != ffi::TRUE
        {
            return Err(());
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
            if let Err(err) = self.runtime.block_on(sink.send(message)) {
                error!("failed to send buffer: {}", err);
                return Err(());
            }
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

    // This is where we deallocate the `Channel` struct, by first
    // casting back to an pointer to an `Arc` and then taking
    // ownership in a box.
    let mut channel = NonNull::new(channel).expect("channel ptr should never be null");
    let channel_data = Box::from_raw(channel.as_mut().method_obj as *mut Arc<Mutex<Channel>>);

    // Simply dropping the Arc is not enough. It is possible that at
    // the moment we dropped it, an existing weak reference had been
    // upgraded, and that another thread is now keeping the data
    // alive. Therefore, we spin here until we know that there are no
    // outstanding strong references. Note that this could block, but
    // it probably won't block for very long.
    //
    // Technically, we could run this loop in a separate thread to
    // avoid blocking the UniMRCP engine, but we'd have to lock the
    // mutex, clone the runtime handle, drop the guard, then pass
    // ownership of the Arc into a newly spawned task.
    let mut arc: Arc<Mutex<Channel>> = *channel_data;
    let mutex = loop {
        arc = match Arc::try_unwrap(arc) {
            Ok(mutex) => break mutex,
            Err(same_arc) => same_arc,
        };
        warn!("Couldn't close channel because there are additional strong pointers. Arc::strong_count() == {}", Arc::strong_count(&arc));

        // Wait to acquire the lock before trying again. This isn't
        // strictly necessary, but it avoids rapidly spinning the loop
        // (assuming that the holder of the other Arc is also locking
        // the mutex).
        arc.lock().ok();
    };

    // Now that we know we have exclusive ownership of the channel
    // data, we can safely notify the engine that we are ready to
    // close, and then drop the data.
    let channel = SendPtr::new(channel.as_ptr());
    mutex.lock().unwrap().runtime.spawn_blocking(move || {
        // This is safe because UniMRCP will not deallocate the
        // channel until after the close response has been sent.
        let channel = channel.get();
        mrcp_engine_channel_close_respond(channel);
    });

    info!("Closed channel");

    ffi::TRUE
}

unsafe extern "C" fn channel_process_request(
    channel: *mut ffi::mrcp_engine_channel_t,
    request: *mut ffi::mrcp_message_t,
) -> ffi::apt_bool_t {
    let channel_data = &mut *((*channel).method_obj as *mut Arc<Mutex<Channel>>);
    let channel_data_weak = Arc::downgrade(channel_data);
    let request = SendPtr::new(request);

    channel_data
        .lock()
        .unwrap()
        .runtime
        .spawn_blocking(move || {
            let channel_data = match channel_data_weak.upgrade() {
                None => return,
                Some(ptr) => ptr,
            };

            let request =
                NonNull::new(request.get()).expect("request pointer should never be null");

            channel_data.lock().unwrap().process_request(request);
        });

    ffi::TRUE
}
