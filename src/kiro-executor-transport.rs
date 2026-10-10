//! Kiro upstream HTTP transport and stream lifecycle helpers.

use base64::Engine;
use serde_json::{json, Value};

use crate::abi::invoke_host_json;
use crate::kiro_event_stream::{
    ClaudeResponseAccumulator, ClaudeSseWriter, KiroEvent, KiroEventStreamDecoder,
    KiroEventStreamError,
};

use super::*;
pub(super) struct PreparedKiroUpstream {
    host_callback_id: String,
    url: String,
    headers: Value,
    body: Vec<u8>,
    pub(super) payload: KiroPayload,
}

pub(super) struct OpenedKiroUpstream {
    stream_id: String,
    status: i64,
}

#[derive(Clone, Debug)]
pub(super) struct KiroExecutorFailure {
    pub(super) status: i64,
    pub(super) message: String,
    pub(super) reason: String,
    pub(super) retry_after_ms: i64,
    pub(super) credential_scoped: bool,
    pub(super) classified: bool,
}

impl KiroExecutorFailure {
    pub(super) fn unknown() -> Self {
        Self {
            status: 502,
            message: "Kiro upstream request failed".into(),
            reason: String::new(),
            retry_after_ms: 0,
            credential_scoped: false,
            classified: false,
        }
    }

    pub(super) fn transport(message: impl Into<String>) -> Self {
        Self {
            status: 0,
            message: message.into(),
            reason: String::new(),
            retry_after_ms: 0,
            credential_scoped: false,
            classified: false,
        }
    }

    pub(super) fn from_stream(error: KiroEventStreamError) -> Self {
        Self {
            status: 200,
            message: error.to_string(),
            reason: String::new(),
            retry_after_ms: 0,
            credential_scoped: false,
            classified: false,
        }
    }

    pub(super) fn retryable(&self) -> bool {
        if self.classified && self.reason == REASON_MONTHLY_REQUEST_COUNT {
            return false;
        }
        if (400..=403).contains(&self.status) {
            return false;
        }
        self.status == 0 || self.status == 429 || self.status >= 500
    }
}

pub(super) struct HostHttpStreamClose {
    stream_id: String,
}

impl Drop for HostHttpStreamClose {
    fn drop(&mut self) {
        close_host_http_stream(&self.stream_id);
    }
}

pub(super) struct PluginStreamClose {
    stream_id: String,
    error: Option<String>,
    closed: bool,
}

impl PluginStreamClose {
    pub(super) fn new(stream_id: &str) -> Self {
        Self {
            stream_id: stream_id.to_owned(),
            error: None,
            closed: false,
        }
    }

    pub(super) fn fail(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    pub(super) fn close(&mut self) {
        if self.closed || self.stream_id.trim().is_empty() {
            return;
        }
        self.closed = true;
        let mut request = json!({"stream_id": self.stream_id});
        if let Some(error) = &self.error {
            if !error.is_empty() {
                request["error"] = json!(error);
            }
        }
        let _ = serde_json::to_vec(&request)
            .ok()
            .and_then(|payload| invoke_host_json("host.stream.close", &payload).ok());
    }
}

impl Drop for PluginStreamClose {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) fn run_kiro_plugin_stream(
    prepared: &PreparedKiroUpstream,
    first: OpenedKiroUpstream,
    plugin_stream: &PluginStreamClose,
) -> Option<String> {
    let output_id = plugin_stream.stream_id.clone();
    let mut first = Some(first);
    for attempt in 1..=MAX_UPSTREAM_ATTEMPTS {
        let mut accumulator = new_response_accumulator(&prepared.payload);
        let mut writer = ClaudeSseWriter::new();
        let mut client_emitted = false;
        let emit_events = |events: &[KiroEvent]| -> Result<(), KiroEventStreamError> {
            for event in events {
                let blocks = accumulator.accept(event)?;
                if blocks.is_empty() {
                    continue;
                }
                if !client_emitted {
                    emit_sse_frames(&output_id, &writer.start(&accumulator)?)?;
                    client_emitted = true;
                }
                emit_sse_frames(&output_id, &writer.blocks(&blocks)?)?;
            }
            Ok(())
        };
        let (emitted, outcome) = if let Some(opened) = first.take() {
            read_opened_kiro_upstream(opened.stream_id, opened.status, emit_events)
        } else {
            consume_kiro_upstream(prepared, attempt, emit_events)
        };
        match outcome {
            Ok(()) => {
                let block_count = accumulator.blocks.len();
                if let Err(error) = accumulator.finish() {
                    return Some(error.to_string());
                }
                if !client_emitted {
                    match writer.start(&accumulator) {
                        Ok(frames) => {
                            if let Err(error) = emit_sse_frames(&output_id, &frames) {
                                return Some(error.to_string());
                            }
                        }
                        Err(error) => return Some(error.to_string()),
                    }
                }
                if block_count < accumulator.blocks.len() {
                    match writer.blocks(&accumulator.blocks[block_count..]) {
                        Ok(frames) => {
                            if let Err(error) = emit_sse_frames(&output_id, &frames) {
                                return Some(error.to_string());
                            }
                        }
                        Err(error) => return Some(error.to_string()),
                    }
                }
                return match writer.finish(&accumulator) {
                    Ok(frames) => emit_sse_frames(&output_id, &frames)
                        .err()
                        .map(|error| error.to_string()),
                    Err(error) => Some(error.to_string()),
                };
            }
            Err(error) => {
                if client_emitted
                    || emitted
                    || !error.retryable()
                    || attempt == MAX_UPSTREAM_ATTEMPTS
                {
                    return Some(error.message);
                }
            }
        }
    }
    Some("Kiro upstream request failed".into())
}

pub(super) fn emit_sse_frames(
    stream_id: &str,
    frames: &[Vec<u8>],
) -> Result<(), KiroEventStreamError> {
    for frame in frames {
        if frame.is_empty() {
            continue;
        }
        emit_kiro_stream_frame(stream_id, frame)
            .map_err(KiroEventStreamError::UpstreamStreamError)?;
    }
    Ok(())
}

pub(super) fn new_response_accumulator(payload: &KiroPayload) -> ClaudeResponseAccumulator {
    ClaudeResponseAccumulator::new(
        payload
            .conversation_state
            .current_message
            .user_input_message
            .model_id
            .clone(),
        payload.tool_name_map.clone().unwrap_or_default(),
        payload.estimated_input_tokens as i64,
    )
}

pub(super) fn prepare_kiro_upstream_request(
    input: &Value,
) -> Result<PreparedKiroUpstream, PrepareKiroError> {
    let model = json_str(input, &["model", "Model"]);
    let payload = decode_request_bytes(input.get("payload").or_else(|| input.get("Payload")))
        .map_err(PrepareKiroError::InvalidRequest)?;
    let (mut kiro_payload, _) = translate_claude_request_to_kiro(&payload, model)
        .map_err(|error| PrepareKiroError::InvalidRequest(error.to_string()))?;
    let credential = decode_request_credential(
        input
            .get("storage_json")
            .or_else(|| input.get("StorageJSON")),
    )?;
    if credential.is_oauth() && credential.profile_arn.is_empty() {
        return Err(PrepareKiroError::Unavailable(
            "Kiro API key unavailable: OAuth credential has no profile_arn".into(),
        ));
    }
    let token = credential
        .bearer_token()
        .map_err(|error| PrepareKiroError::Unavailable(error.to_string()))?;
    if credential.is_oauth() {
        kiro_payload.profile_arn = Some(credential.profile_arn.clone());
    }
    let body = serde_json::to_vec(&kiro_payload).map_err(|error| {
        PrepareKiroError::InvalidRequest(format!("encode Kiro request: {error}"))
    })?;
    let region = credential.runtime_region();
    let endpoint = format!("https://runtime.{region}.kiro.dev/");
    if !is_kiro_runtime_https_url(&endpoint, &region) {
        return Err(PrepareKiroError::InvalidRequest(
            "invalid Kiro endpoint".into(),
        ));
    }
    let config = loaded_kiro_config();
    let machine = kiro_machine_id(&credential, &token);
    let user_agent = format!(
        "aws-sdk-js/1.0.34 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#1.0.34 m/E KiroIDE-{}-{}",
        config.system_version, config.node_version, config.kiro_version, machine
    );
    let amz_user_agent = format!(
        "aws-sdk-js/1.0.34 KiroIDE-{}-{}",
        config.kiro_version, machine
    );
    let mut headers = json!({
        "Accept": ["*/*"],
        "Content-Type": ["application/x-amz-json-1.0"],
        "User-Agent": [user_agent],
        "X-Amz-Target": [KIRO_AMZ_TARGET],
        "X-Amz-User-Agent": [amz_user_agent],
        "X-Amzn-Codewhisperer-Optout": ["true"]
    });
    apply_kiro_auth_headers(&mut headers, &credential, &token);
    Ok(PreparedKiroUpstream {
        host_callback_id: json_str(input, &["host_callback_id", "HostCallbackID"]).to_owned(),
        url: endpoint,
        headers,
        body,
        payload: kiro_payload,
    })
}

#[derive(Debug)]
pub(super) enum PrepareKiroError {
    Unavailable(String),
    InvalidRequest(String),
}

impl std::fmt::Display for PrepareKiroError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::InvalidRequest(message) => {
                formatter.write_str(message)
            }
        }
    }
}

pub(super) fn prepare_request_error_envelope(error: &PrepareKiroError) -> Vec<u8> {
    match error {
        PrepareKiroError::Unavailable(message) => {
            plugin_error_envelope("invalid_auth", message, 401, false, 0, false)
        }
        PrepareKiroError::InvalidRequest(message) => {
            plugin_error_envelope("invalid_request", message, 400, false, 0, false)
        }
    }
}

pub(super) fn open_kiro_upstream(
    prepared: &PreparedKiroUpstream,
    attempt: u32,
) -> Result<OpenedKiroUpstream, KiroExecutorFailure> {
    let mut headers = prepared.headers.clone();
    set_header(
        &mut headers,
        "Amz-Sdk-Request",
        &format!("attempt={attempt}; max={MAX_UPSTREAM_ATTEMPTS}"),
    );
    set_header(
        &mut headers,
        "Amz-Sdk-Invocation-Id",
        &generate_kiro_executor_uuid(),
    );
    let callback_request = json!({
        "host_callback_id": prepared.host_callback_id,
        "method": "POST",
        "url": prepared.url,
        "headers": headers,
        "body": base64::engine::general_purpose::STANDARD.encode(&prepared.body)
    });
    let raw = invoke_host_json(
        "host.http.do_stream",
        &serde_json::to_vec(&callback_request)
            .map_err(|error| KiroExecutorFailure::transport(error.to_string()))?,
    )
    .map_err(|error| {
        KiroExecutorFailure::transport(format!("start Kiro upstream stream: {error}"))
    })?;
    let response: Value = serde_json::from_slice(&raw).map_err(|error| {
        KiroExecutorFailure::transport(format!("decode Kiro upstream response: {error}"))
    })?;
    let status = json_i64(&response, &["status_code", "StatusCode"]).unwrap_or(0);
    let stream_id = json_str(&response, &["stream_id", "StreamID"]).to_owned();
    if stream_id.trim().is_empty() {
        return Err(KiroExecutorFailure {
            status,
            message: "Kiro upstream returned no stream".into(),
            reason: String::new(),
            retry_after_ms: 0,
            credential_scoped: false,
            classified: false,
        });
    }
    if status != 200 {
        let body = read_error_body(&stream_id, MAX_ERROR_BODY_BYTES);
        close_host_http_stream(&stream_id);
        return Err(classify_kiro_upstream_error(
            status,
            response.get("headers").or_else(|| response.get("Headers")),
            &body,
        ));
    }
    Ok(OpenedKiroUpstream { stream_id, status })
}

pub(super) fn consume_kiro_upstream<F>(
    prepared: &PreparedKiroUpstream,
    attempt: u32,
    on_events: F,
) -> (bool, Result<(), KiroExecutorFailure>)
where
    F: FnMut(&[KiroEvent]) -> Result<(), KiroEventStreamError>,
{
    match open_kiro_upstream(prepared, attempt) {
        Ok(opened) => read_opened_kiro_upstream(opened.stream_id, opened.status, on_events),
        Err(error) => (false, Err(error)),
    }
}

pub(super) fn read_opened_kiro_upstream<F>(
    stream_id: String,
    status: i64,
    mut on_events: F,
) -> (bool, Result<(), KiroExecutorFailure>)
where
    F: FnMut(&[KiroEvent]) -> Result<(), KiroEventStreamError>,
{
    let _guard = HostHttpStreamClose {
        stream_id: stream_id.clone(),
    };
    let mut decoder = KiroEventStreamDecoder::default();
    let mut emitted = false;
    loop {
        let raw = match serde_json::to_vec(&json!({"stream_id": stream_id})) {
            Ok(payload) => match invoke_host_json("host.http.stream_read", &payload) {
                Ok(raw) => raw,
                Err(error) => {
                    return (
                        emitted,
                        Err(KiroExecutorFailure {
                            status,
                            message: format!("read Kiro upstream stream: {error}"),
                            reason: String::new(),
                            retry_after_ms: 0,
                            credential_scoped: false,
                            classified: false,
                        }),
                    );
                }
            },
            Err(error) => {
                return (
                    emitted,
                    Err(KiroExecutorFailure {
                        status,
                        message: format!("encode Kiro stream read: {error}"),
                        reason: String::new(),
                        retry_after_ms: 0,
                        credential_scoped: false,
                        classified: false,
                    }),
                );
            }
        };
        let chunk: Value = match serde_json::from_slice(&raw) {
            Ok(chunk) => chunk,
            Err(error) => {
                return (
                    emitted,
                    Err(KiroExecutorFailure {
                        status,
                        message: format!("decode Kiro stream read: {error}"),
                        reason: String::new(),
                        retry_after_ms: 0,
                        credential_scoped: false,
                        classified: false,
                    }),
                );
            }
        };
        if let Some(error) = chunk
            .get("error")
            .or_else(|| chunk.get("Error"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return (
                emitted,
                Err(KiroExecutorFailure {
                    status,
                    message: format!("Kiro upstream stream: {error}"),
                    reason: String::new(),
                    retry_after_ms: 0,
                    credential_scoped: false,
                    classified: false,
                }),
            );
        }
        let bytes =
            match decode_request_bytes(chunk.get("payload").or_else(|| chunk.get("Payload"))) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return (
                        emitted,
                        Err(KiroExecutorFailure {
                            status,
                            message: error,
                            reason: String::new(),
                            retry_after_ms: 0,
                            credential_scoped: false,
                            classified: false,
                        }),
                    );
                }
            };
        if !bytes.is_empty() {
            let events = match decoder.feed(&bytes) {
                Ok(events) => events,
                Err(error) => {
                    return (
                        emitted,
                        Err(KiroExecutorFailure {
                            status,
                            message: error.to_string(),
                            reason: String::new(),
                            retry_after_ms: 0,
                            credential_scoped: false,
                            classified: false,
                        }),
                    );
                }
            };
            if !events.is_empty() {
                emitted = true;
                if let Err(error) = on_events(&events) {
                    return (emitted, Err(KiroExecutorFailure::from_stream(error)));
                }
            }
        }
        if chunk
            .get("done")
            .or_else(|| chunk.get("Done"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            break;
        }
    }
    if let Err(error) = decoder.finish() {
        return (
            emitted,
            Err(KiroExecutorFailure {
                status,
                message: error.to_string(),
                reason: String::new(),
                retry_after_ms: 0,
                credential_scoped: false,
                classified: false,
            }),
        );
    }
    (emitted, Ok(()))
}

pub(super) fn read_error_body(stream_id: &str, max_bytes: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < max_bytes {
        let Ok(raw) = serde_json::to_vec(&json!({"stream_id": stream_id})) else {
            break;
        };
        let Ok(response) = invoke_host_json("host.http.stream_read", &raw) else {
            break;
        };
        let Ok(chunk) = serde_json::from_slice::<Value>(&response) else {
            break;
        };
        let Ok(mut payload) =
            decode_request_bytes(chunk.get("payload").or_else(|| chunk.get("Payload")))
        else {
            break;
        };
        let remaining = max_bytes - body.len();
        if payload.len() > remaining {
            payload.truncate(remaining);
        }
        body.extend_from_slice(&payload);
        if chunk
            .get("done")
            .or_else(|| chunk.get("Done"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || chunk
                .get("error")
                .or_else(|| chunk.get("Error"))
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        {
            break;
        }
    }
    body
}

pub(super) fn close_host_http_stream(stream_id: &str) {
    if stream_id.trim().is_empty() {
        return;
    }
    let Ok(payload) = serde_json::to_vec(&json!({"stream_id": stream_id})) else {
        return;
    };
    let _ = invoke_host_json("host.http.stream_close", &payload);
}

pub(super) fn emit_kiro_stream_frame(stream_id: &str, frame: &[u8]) -> Result<(), String> {
    let payload = base64::engine::general_purpose::STANDARD.encode(frame);
    invoke_host_json(
        "host.stream.emit",
        &serde_json::to_vec(&json!({"stream_id": stream_id, "payload": payload}))
            .map_err(|error| error.to_string())?,
    )?;
    Ok(())
}
