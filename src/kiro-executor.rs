//! Kiro executor orchestration through CPA host HTTP callbacks.

use std::cell::Cell;
#[cfg(test)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{json, Map, Value};
use time::{Date, Duration as TimeDuration, Month, OffsetDateTime, Time};

use crate::abi::invoke_host_json;
use crate::config::loaded_kiro_config;
use crate::kiro_credentials::{parse_kiro_credential, KiroAuthMethod, KiroCredential};
use crate::kiro_event_stream::{
    ClaudeResponseAccumulator, ClaudeSseWriter, KiroEvent, KiroEventStreamDecoder,
    KiroEventStreamError,
};
use crate::kiro_request_transform::{translate_claude_request_to_kiro, KiroPayload};

const KIRO_AMZ_TARGET: &str = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse";
const MAX_UPSTREAM_ATTEMPTS: u32 = 2;
const MAX_ERROR_BODY_BYTES: usize = 4096;
const MAX_RETRY_AFTER_HINT: TimeDuration = TimeDuration::hours(24);
const REASON_MONTHLY_REQUEST_COUNT: &str = "MONTHLY_REQUEST_COUNT";
const REASON_INSUFFICIENT_MODEL_CAPACITY: &str = "INSUFFICIENT_MODEL_CAPACITY";
const REASON_USER_REQUEST_RATE_EXCEEDED: &str = "USER_REQUEST_RATE_EXCEEDED";
const REASON_CONTENT_LENGTH_EXCEEDS_THRESHOLD: &str = "CONTENT_LENGTH_EXCEEDS_THRESHOLD";
const REASON_REQUEST_BODY_INVALID: &str = "REQUEST_BODY_INVALID";
static KIRO_EXECUTOR_UUID_COUNTER: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static KIRO_UPSTREAM_NOW_OVERRIDE: Cell<Option<OffsetDateTime>> = const { Cell::new(None) };
}

/// Executes a non-streaming Kiro request through `host.http.do_stream`.
pub fn execute_kiro_request(request: &[u8]) -> Result<Vec<u8>, String> {
    let input: Value = serde_json::from_slice(request)
        .map_err(|error| format!("decode executor request: {error}"))?;
    let prepared = match prepare_kiro_upstream_request(&input) {
        Ok(prepared) => prepared,
        Err(error) => return Ok(prepare_request_error_envelope(&error)),
    };
    let mut last_error: Option<KiroExecutorFailure> = None;
    for attempt in 1..=MAX_UPSTREAM_ATTEMPTS {
        let mut accumulator = new_response_accumulator(&prepared.payload);
        let (emitted, outcome) = consume_kiro_upstream(&prepared, attempt, |events| {
            for event in events {
                accumulator.accept(event)?;
            }
            Ok(())
        });
        match outcome {
            Ok(()) => match accumulator.finish() {
                Ok(()) => {
                    let body = accumulator.response_json();
                    let payload = serde_json::to_vec(&body)
                        .map_err(|error| format!("encode Claude response: {error}"))?;
                    return Ok(ok_executor_envelope(json!({
                        "Payload": base64::engine::general_purpose::STANDARD.encode(payload),
                        "Headers": {"Content-Type": ["application/json"]},
                        "Metadata": {"kiro_credits": accumulator.credits}
                    })));
                }
                Err(error) => last_error = Some(KiroExecutorFailure::from_stream(error)),
            },
            Err(error) => last_error = Some(error),
        }
        let failure = last_error
            .as_ref()
            .cloned()
            .unwrap_or_else(KiroExecutorFailure::unknown);
        if emitted || !failure.retryable() || attempt == MAX_UPSTREAM_ATTEMPTS {
            return Ok(upstream_error_envelope(&failure));
        }
    }
    Ok(upstream_error_envelope(
        &last_error.unwrap_or_else(KiroExecutorFailure::unknown),
    ))
}

/// Forwards an executor-owned HTTP request through CPA host transport.
pub fn execute_kiro_http_request(request: &[u8]) -> Result<Vec<u8>, String> {
    let input: Value = serde_json::from_slice(request)
        .map_err(|error| format!("decode executor HTTP request: {error}"))?;
    let credential = match decode_request_credential(
        input
            .get("storage_json")
            .or_else(|| input.get("StorageJSON")),
    ) {
        Ok(credential) => credential,
        Err(error) => {
            return Ok(plugin_error_envelope(
                "invalid_auth",
                &error.to_string(),
                401,
                false,
                0,
                false,
            ))
        }
    };
    let region = credential.runtime_region();
    let endpoint = format!("https://runtime.{region}.kiro.dev/");
    let url = json_str(&input, &["url", "URL"]);
    if !is_kiro_runtime_https_url(url, &region) {
        return Ok(plugin_error_envelope(
            "invalid_request",
            "Kiro HTTP bridge only permits the configured runtime host",
            400,
            false,
            0,
            false,
        ));
    }
    let token = match credential.bearer_token() {
        Ok(token) => token,
        Err(error) => {
            return Ok(plugin_error_envelope(
                "invalid_auth",
                &error.to_string(),
                401,
                false,
                0,
                false,
            ))
        }
    };
    let mut headers = input
        .get("headers")
        .or_else(|| input.get("Headers"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    apply_kiro_auth_headers(&mut headers, &credential, &token);
    let callback_request = json!({
        "host_callback_id": json_str(&input, &["host_callback_id", "HostCallbackID"]),
        "method": json_str(&input, &["method", "Method"]),
        "url": if url.is_empty() { endpoint } else { url.to_owned() },
        "headers": headers,
        "body": input.get("body").or_else(|| input.get("Body")).cloned().unwrap_or(Value::Null)
    });
    match invoke_host_json(
        "host.http.do",
        &serde_json::to_vec(&callback_request).map_err(|error| error.to_string())?,
    ) {
        Ok(response) => {
            let response: Value = serde_json::from_slice(&response)
                .map_err(|error| format!("decode Kiro HTTP bridge response: {error}"))?;
            Ok(ok_executor_envelope(response))
        }
        Err(error) => Ok(upstream_error_envelope(&KiroExecutorFailure::transport(
            error,
        ))),
    }
}

/// Executes a Kiro streaming request and closes the upstream and output streams.
pub fn execute_kiro_stream_request(request: &[u8]) -> Result<Vec<u8>, String> {
    let input: Value = serde_json::from_slice(request)
        .map_err(|error| format!("decode streaming executor request: {error}"))?;
    let output_id = json_str(&input, &["stream_id", "StreamID"]);
    if output_id.trim().is_empty() {
        return Ok(plugin_error_envelope(
            "invalid_request",
            "stream_id is required",
            400,
            false,
            0,
            false,
        ));
    }
    let prepared = match prepare_kiro_upstream_request(&input) {
        Ok(prepared) => prepared,
        Err(error) => return Ok(prepare_request_error_envelope(&error)),
    };
    let mut opened = None;
    let mut last_error = None;
    for attempt in 1..=MAX_UPSTREAM_ATTEMPTS {
        match open_kiro_upstream(&prepared, attempt) {
            Ok(value) => {
                opened = Some(value);
                break;
            }
            Err(error) => {
                let retryable = error.retryable();
                last_error = Some(error);
                if !retryable || attempt == MAX_UPSTREAM_ATTEMPTS {
                    return Ok(upstream_error_envelope(
                        last_error
                            .as_ref()
                            .unwrap_or(&KiroExecutorFailure::unknown()),
                    ));
                }
            }
        }
    }
    let Some(first) = opened else {
        return Ok(upstream_error_envelope(
            &last_error.unwrap_or_else(KiroExecutorFailure::unknown),
        ));
    };
    let mut plugin_stream = PluginStreamClose::new(output_id);
    let mut terminal = run_kiro_plugin_stream(&prepared, first, &plugin_stream);
    if let Some(error) = terminal.take() {
        plugin_stream.fail(error);
    }
    plugin_stream.close();
    Ok(ok_executor_envelope(
        json!({"headers": {"Content-Type": ["text/event-stream"]}}),
    ))
}

struct PreparedKiroUpstream {
    host_callback_id: String,
    url: String,
    headers: Value,
    body: Vec<u8>,
    payload: KiroPayload,
}

struct OpenedKiroUpstream {
    stream_id: String,
    status: i64,
}

#[derive(Clone, Debug)]
struct KiroExecutorFailure {
    status: i64,
    message: String,
    reason: String,
    retry_after_ms: i64,
    credential_scoped: bool,
    classified: bool,
}

impl KiroExecutorFailure {
    fn unknown() -> Self {
        Self {
            status: 502,
            message: "Kiro upstream request failed".into(),
            reason: String::new(),
            retry_after_ms: 0,
            credential_scoped: false,
            classified: false,
        }
    }

    fn transport(message: impl Into<String>) -> Self {
        Self {
            status: 0,
            message: message.into(),
            reason: String::new(),
            retry_after_ms: 0,
            credential_scoped: false,
            classified: false,
        }
    }

    fn from_stream(error: KiroEventStreamError) -> Self {
        Self {
            status: 200,
            message: error.to_string(),
            reason: String::new(),
            retry_after_ms: 0,
            credential_scoped: false,
            classified: false,
        }
    }

    fn retryable(&self) -> bool {
        if self.classified && self.reason == REASON_MONTHLY_REQUEST_COUNT {
            return false;
        }
        if (400..=403).contains(&self.status) {
            return false;
        }
        self.status == 0 || self.status == 429 || self.status >= 500
    }
}

struct HostHttpStreamClose {
    stream_id: String,
}

impl Drop for HostHttpStreamClose {
    fn drop(&mut self) {
        close_host_http_stream(&self.stream_id);
    }
}

struct PluginStreamClose {
    stream_id: String,
    error: Option<String>,
    closed: bool,
}

impl PluginStreamClose {
    fn new(stream_id: &str) -> Self {
        Self {
            stream_id: stream_id.to_owned(),
            error: None,
            closed: false,
        }
    }

    fn fail(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    fn close(&mut self) {
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

fn run_kiro_plugin_stream(
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

fn emit_sse_frames(stream_id: &str, frames: &[Vec<u8>]) -> Result<(), KiroEventStreamError> {
    for frame in frames {
        if frame.is_empty() {
            continue;
        }
        emit_kiro_stream_frame(stream_id, frame)
            .map_err(KiroEventStreamError::UpstreamStreamError)?;
    }
    Ok(())
}

fn new_response_accumulator(payload: &KiroPayload) -> ClaudeResponseAccumulator {
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

fn prepare_kiro_upstream_request(input: &Value) -> Result<PreparedKiroUpstream, PrepareKiroError> {
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
enum PrepareKiroError {
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

fn prepare_request_error_envelope(error: &PrepareKiroError) -> Vec<u8> {
    match error {
        PrepareKiroError::Unavailable(message) => {
            plugin_error_envelope("invalid_auth", message, 401, false, 0, false)
        }
        PrepareKiroError::InvalidRequest(message) => {
            plugin_error_envelope("invalid_request", message, 400, false, 0, false)
        }
    }
}

fn open_kiro_upstream(
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

fn consume_kiro_upstream<F>(
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

fn read_opened_kiro_upstream<F>(
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

fn read_error_body(stream_id: &str, max_bytes: usize) -> Vec<u8> {
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

fn close_host_http_stream(stream_id: &str) {
    if stream_id.trim().is_empty() {
        return;
    }
    let Ok(payload) = serde_json::to_vec(&json!({"stream_id": stream_id})) else {
        return;
    };
    let _ = invoke_host_json("host.http.stream_close", &payload);
}

fn emit_kiro_stream_frame(stream_id: &str, frame: &[u8]) -> Result<(), String> {
    let payload = base64::engine::general_purpose::STANDARD.encode(frame);
    invoke_host_json(
        "host.stream.emit",
        &serde_json::to_vec(&json!({"stream_id": stream_id, "payload": payload}))
            .map_err(|error| error.to_string())?,
    )?;
    Ok(())
}

fn classify_kiro_upstream_error(
    status: i64,
    headers: Option<&Value>,
    body: &[u8],
) -> KiroExecutorFailure {
    let detail = limited_error_body(body);
    let reason = extract_reason_code(body);
    let mut failure = KiroExecutorFailure {
        status,
        message: format!("Kiro upstream HTTP {status}: {detail}"),
        reason: reason.clone(),
        retry_after_ms: 0,
        credential_scoped: false,
        classified: true,
    };
    if reason == REASON_MONTHLY_REQUEST_COUNT {
        let now = kiro_upstream_now();
        failure.status = 429;
        failure.credential_scoped = true;
        failure.retry_after_ms = (next_month_start(now) - now).whole_milliseconds() as i64;
    } else if status == 403 && is_invalid_bearer_token(body) {
        failure.status = 401;
    } else if status == 429 {
        failure.retry_after_ms = retry_after_from_headers(headers);
    }
    failure
}

fn next_month_start(now: OffsetDateTime) -> OffsetDateTime {
    let date = now.date();
    let (year, month) = match date.month() {
        Month::January => (date.year(), Month::February),
        Month::February => (date.year(), Month::March),
        Month::March => (date.year(), Month::April),
        Month::April => (date.year(), Month::May),
        Month::May => (date.year(), Month::June),
        Month::June => (date.year(), Month::July),
        Month::July => (date.year(), Month::August),
        Month::August => (date.year(), Month::September),
        Month::September => (date.year(), Month::October),
        Month::October => (date.year(), Month::November),
        Month::November => (date.year(), Month::December),
        Month::December => (date.year() + 1, Month::January),
    };
    Date::from_calendar_date(year, month, 1)
        .map(|start| start.with_time(Time::MIDNIGHT).assume_utc())
        .unwrap_or(now)
}

fn extract_reason_code(body: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(body);
    let trimmed = trimmed.trim();
    if trimmed.starts_with('{') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            if let Some(reason) = parsed
                .get("reason")
                .or_else(|| parsed.get("reasonCode"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                return reason.to_owned();
            }
        }
    }
    for marker in [
        REASON_MONTHLY_REQUEST_COUNT,
        REASON_INSUFFICIENT_MODEL_CAPACITY,
        REASON_USER_REQUEST_RATE_EXCEEDED,
        REASON_CONTENT_LENGTH_EXCEEDS_THRESHOLD,
        REASON_REQUEST_BODY_INVALID,
    ] {
        if trimmed.contains(marker) {
            return marker.to_owned();
        }
    }
    String::new()
}

fn is_invalid_bearer_token(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    text.contains("bearer token included in the request is invalid")
        || text.contains("invalid token")
        || text.contains("token has expired")
}

fn retry_after_from_headers(headers: Option<&Value>) -> i64 {
    let Some(headers) = headers else {
        return 0;
    };
    if let Some(value) = header_get(headers, "Retry-After-Ms") {
        if let Ok(millis) = value.parse::<i64>() {
            if millis > 0 {
                return clamp_retry_after_ms(millis);
            }
        }
    }
    for name in ["Retry-After", "X-Ratelimit-Reset-After"] {
        let Some(value) = header_get(headers, name) else {
            continue;
        };
        if let Ok(seconds) = value.parse::<f64>() {
            if seconds > 0.0 {
                return clamp_retry_after_ms((seconds * 1000.0) as i64);
            }
        }
        if let Some(at) = parse_http_date(&value) {
            let wait = at - kiro_upstream_now();
            if wait > TimeDuration::ZERO {
                return clamp_retry_after_ms(wait.whole_milliseconds() as i64);
            }
        }
    }
    0
}

fn clamp_retry_after_ms(wait: i64) -> i64 {
    wait.min(MAX_RETRY_AFTER_HINT.whole_milliseconds() as i64)
}

fn limited_error_body(body: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(body);
    let trimmed = trimmed.trim().as_bytes();
    let limit = trimmed.len().min(1024);
    String::from_utf8_lossy(&trimmed[..limit]).into_owned()
}

fn kiro_upstream_now() -> OffsetDateTime {
    KIRO_UPSTREAM_NOW_OVERRIDE
        .with(|cell| cell.get())
        .unwrap_or_else(OffsetDateTime::now_utc)
}

fn header_get(headers: &Value, name: &str) -> Option<String> {
    let object = headers.as_object()?;
    object.iter().find_map(|(key, value)| {
        if !key.eq_ignore_ascii_case(name) {
            return None;
        }
        match value {
            Value::Array(values) => values
                .iter()
                .find_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            Value::String(value) => {
                let value = value.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                }
            }
            _ => None,
        }
    })
}

fn parse_http_date(value: &str) -> Option<OffsetDateTime> {
    let value = value.trim();
    let rest = value.split_once(", ")?.1;
    let mut parts = rest.split_whitespace();
    let day = parts.next()?.parse::<u8>().ok()?;
    let month = parse_http_month(parts.next()?)?;
    let year = parts.next()?.parse::<i32>().ok()?;
    let time = parts.next()?;
    let zone = parts.next()?;
    if zone != "GMT" && zone != "UTC" {
        return None;
    }
    let mut hms = time.split(':');
    let hour = hms.next()?.parse::<u8>().ok()?;
    let minute = hms.next()?.parse::<u8>().ok()?;
    let second = hms.next()?.parse::<u8>().ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    Some(date.with_time(time).assume_utc())
}

fn parse_http_month(value: &str) -> Option<Month> {
    Some(match value {
        "Jan" => Month::January,
        "Feb" => Month::February,
        "Mar" => Month::March,
        "Apr" => Month::April,
        "May" => Month::May,
        "Jun" => Month::June,
        "Jul" => Month::July,
        "Aug" => Month::August,
        "Sep" => Month::September,
        "Oct" => Month::October,
        "Nov" => Month::November,
        "Dec" => Month::December,
        _ => return None,
    })
}

fn upstream_error_envelope(failure: &KiroExecutorFailure) -> Vec<u8> {
    let mut status = failure.status;
    if status == 0 {
        status = 502;
    }
    let code = if failure.classified && failure.reason == REASON_MONTHLY_REQUEST_COUNT {
        "quota_exhausted"
    } else if status == 401 || status == 403 {
        "invalid_auth"
    } else if status == 429 {
        "rate_limited"
    } else if status == 402 {
        "billing_required"
    } else {
        "upstream_error"
    };
    plugin_error_envelope(
        code,
        &failure.message,
        status,
        failure.retryable(),
        if failure.classified {
            failure.retry_after_ms
        } else {
            0
        },
        failure.classified && failure.credential_scoped,
    )
}

fn plugin_error_envelope(
    code: &str,
    message: &str,
    http_status: i64,
    retryable: bool,
    retry_after_ms: i64,
    credential_scoped: bool,
) -> Vec<u8> {
    let mut error = Map::new();
    error.insert("code".into(), json!(code));
    error.insert("message".into(), json!(message));
    if http_status != 0 {
        error.insert("http_status".into(), json!(http_status));
    }
    if retryable {
        error.insert("retryable".into(), json!(true));
    }
    if retry_after_ms != 0 {
        error.insert("retry_after_ms".into(), json!(retry_after_ms));
    }
    if credential_scoped {
        error.insert("credential_scoped".into(), json!(true));
    }
    json!({"ok": false, "error": error})
        .to_string()
        .into_bytes()
}

fn ok_executor_envelope(value: Value) -> Vec<u8> {
    json!({"ok": true, "result": value})
        .to_string()
        .into_bytes()
}

fn apply_kiro_auth_headers(headers: &mut Value, credential: &KiroCredential, token: &str) {
    set_header(headers, "Authorization", &format!("Bearer {token}"));
    match credential.auth_method {
        KiroAuthMethod::ApiKey => set_header(headers, "Tokentype", "API_KEY"),
        KiroAuthMethod::ExternalIdp => set_header(headers, "Tokentype", "EXTERNAL_IDP"),
        _ => remove_header(headers, "Tokentype"),
    }
}

fn set_header(headers: &mut Value, name: &str, value: &str) {
    if !headers.is_object() {
        *headers = json!({});
    }
    if let Some(object) = headers.as_object_mut() {
        object.insert(name.to_owned(), json!([value]));
    }
}

fn remove_header(headers: &mut Value, name: &str) {
    if let Some(object) = headers.as_object_mut() {
        object.retain(|key, _| !key.eq_ignore_ascii_case(name));
    }
}

fn kiro_machine_id(credential: &KiroCredential, token: &str) -> String {
    let seed = if credential.is_oauth() {
        format!(
            "oauth:{}",
            first_non_empty(&[&credential.profile_arn, &credential.refresh_token, token])
        )
    } else {
        token.to_owned()
    };
    sha256_hex(format!("KiroAPIKey/{seed}").as_bytes())
}

fn first_non_empty(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn is_kiro_runtime_https_url(url: &str, region: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    let host = host.split('@').next_back().unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default();
    host == format!("runtime.{region}.kiro.dev")
}

fn generate_kiro_executor_uuid() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64);
    let counter = KIRO_EXECUTOR_UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{now:016x}-{counter:08x}")
}

fn sha256_hex(input: &[u8]) -> String {
    sha256_digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_digest(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c3_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut state = [
        0x6a09_e667_u32,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (input.len() as u64).saturating_mul(8);
    let mut data = input.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in w.iter_mut().enumerate().take(16) {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut out = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn decode_request_credential(storage: Option<&Value>) -> Result<KiroCredential, PrepareKiroError> {
    let bytes = decode_request_bytes(storage).map_err(PrepareKiroError::InvalidRequest)?;
    match parse_kiro_credential(&bytes) {
        Ok(Some(credential)) => Ok(credential),
        Ok(None) => Err(PrepareKiroError::InvalidRequest(
            "selected auth is not a Kiro credential".into(),
        )),
        Err(error) => {
            if matches!(
                error,
                crate::kiro_credentials::KiroCredentialError::ApiKeyUnavailable(_)
            ) {
                Err(PrepareKiroError::Unavailable(error.to_string()))
            } else {
                Err(PrepareKiroError::InvalidRequest(error.to_string()))
            }
        }
    }
}

fn decode_request_bytes(value: Option<&Value>) -> Result<Vec<u8>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Some(encoded) = value.as_str() {
        return match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(bytes) => Ok(bytes),
            Err(_) => Ok(encoded.as_bytes().to_vec()),
        };
    }
    if let Some(bytes) = value.as_array().and_then(|values| json_byte_array(values)) {
        return Ok(bytes);
    }
    serde_json::to_vec(value).map_err(|error| format!("encode JSON payload: {error}"))
}

fn json_byte_array(values: &[Value]) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(values.len());
    for value in values {
        bytes.push(u8::try_from(value.as_u64()?).ok()?);
    }
    Some(bytes)
}

fn json_str<'a>(value: &'a Value, names: &[&str]) -> &'a str {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .unwrap_or_default()
}

fn json_i64(value: &Value, names: &[&str]) -> Option<i64> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_i64))
}

#[cfg(test)]
fn convert_kiro_events_to_claude_content(events: &[KiroEvent]) -> (Vec<Value>, Value, String) {
    let mut accumulator = ClaudeResponseAccumulator::new(String::new(), HashMap::new(), 0);
    for event in events {
        let _ = accumulator.accept(event);
    }
    let _ = accumulator.finish();
    let response = accumulator.response_json();
    (
        response
            .get("content")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        response
            .get("usage")
            .cloned()
            .unwrap_or_else(|| json!({"input_tokens": 0, "output_tokens": 0})),
        accumulator.stop_reason,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Map, Value};
    use time::Month;

    use super::{
        classify_kiro_upstream_error, convert_kiro_events_to_claude_content, next_month_start,
        KIRO_UPSTREAM_NOW_OVERRIDE,
    };
    use crate::kiro_event_stream::KiroEvent;
    use time::{Date, OffsetDateTime, Time};

    #[test]
    fn response_conversion_omits_unreplayable_reasoning_and_keeps_usage() {
        let events = vec![
            KiroEvent {
                event_type: "reasoningContentEvent".into(),
                payload: serde_json::from_value(json!({"content": "hidden chain of thought"}))
                    .expect("object payload"),
            },
            KiroEvent {
                event_type: "assistantResponseEvent".into(),
                payload: serde_json::from_value(
                    json!({"content": "answer", "usage": {"inputTokens": 7, "outputTokens": 2}}),
                )
                .expect("object payload"),
            },
        ];
        let (content, usage, stop_reason) = convert_kiro_events_to_claude_content(&events);
        assert_eq!(content, vec![json!({"type": "text", "text": "answer"})]);
        assert_eq!(usage["input_tokens"], 7);
        assert_eq!(usage["output_tokens"], 2);
        assert_eq!(stop_reason, "end_turn");
        assert_eq!(content[0].get("stop_sequence"), None);
    }

    #[test]
    fn response_conversion_assembles_tool_use_fragments() {
        let mut first = Map::new();
        first.insert("name".into(), json!("search"));
        first.insert("input".into(), json!("{\"query\":"));
        let mut second = Map::new();
        second.insert("toolUseId".into(), json!("call-1"));
        second.insert("name".into(), json!("search"));
        second.insert("input".into(), json!("\"kiro\"}"));
        second.insert("stop".into(), json!(true));
        let events = vec![
            KiroEvent {
                event_type: "toolUseEvent".into(),
                payload: first,
            },
            KiroEvent {
                event_type: "toolUseEvent".into(),
                payload: second,
            },
        ];
        let (content, usage, stop_reason) = convert_kiro_events_to_claude_content(&events);
        assert_eq!(content[0]["type"], "tool_use");
        assert_eq!(content[0]["id"], "call-1");
        assert_eq!(content[0]["input"]["query"], "kiro");
        assert_eq!(usage["input_tokens"], 0);
        assert_eq!(stop_reason, "tool_use");
    }

    #[test]
    fn monthly_quota_is_credential_scoped_until_reset() {
        let now = OffsetDateTime::new_utc(
            Date::from_calendar_date(2026, Month::October, 10).expect("date"),
            Time::from_hms(15, 30, 0).expect("time"),
        );
        KIRO_UPSTREAM_NOW_OVERRIDE.with(|cell| cell.set(Some(now)));
        let failure = classify_kiro_upstream_error(
            402,
            None,
            br#"{"message":"Free tier limit reached","reason":"MONTHLY_REQUEST_COUNT"}"#,
        );
        KIRO_UPSTREAM_NOW_OVERRIDE.with(|cell| cell.set(None));
        assert_eq!(failure.status, 429);
        assert!(failure.credential_scoped);
        assert!(!failure.retryable());
        assert_eq!(
            failure.retry_after_ms,
            (next_month_start(now) - now).whole_milliseconds() as i64
        );
        let envelope: Value =
            serde_json::from_slice(&super::upstream_error_envelope(&failure)).expect("json");
        assert_eq!(envelope["error"]["code"], "quota_exhausted");
        assert_eq!(envelope["error"]["http_status"], 429);
        assert_eq!(envelope["error"]["credential_scoped"], true);
    }

    #[test]
    fn short_rate_limit_keeps_header_hint() {
        let failure = classify_kiro_upstream_error(
            429,
            Some(&json!({"Retry-After": ["7"]})),
            br#"{"message":"Too many requests","reason":"USER_REQUEST_RATE_EXCEEDED"}"#,
        );
        assert_eq!(failure.status, 429);
        assert!(!failure.credential_scoped);
        assert!(failure.retryable());
        assert_eq!(failure.retry_after_ms, 7000);
        let envelope: Value =
            serde_json::from_slice(&super::upstream_error_envelope(&failure)).expect("json");
        assert_eq!(envelope["error"]["code"], "rate_limited");
        assert_eq!(envelope["error"]["retryable"], true);
        assert_eq!(envelope["error"]["retry_after_ms"], 7000);
    }

    #[test]
    fn invalid_bearer_token_is_reported_as_unauthorized() {
        let failure = classify_kiro_upstream_error(
            403,
            None,
            br#"{"__type":"com.amazon.kiro.runtimeservice#AccessDeniedException","message":"The bearer token included in the request is invalid."}"#,
        );
        assert_eq!(failure.status, 401);
        assert!(!failure.credential_scoped);
        assert!(!failure.retryable());
        let envelope: Value =
            serde_json::from_slice(&super::upstream_error_envelope(&failure)).expect("json");
        assert_eq!(envelope["error"]["code"], "invalid_auth");
        assert!(!envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains("oauth-access"));
    }

    #[test]
    fn monthly_quota_retry_after_matches_frozen_fixture_clock() {
        let now = OffsetDateTime::new_utc(
            Date::from_calendar_date(2026, Month::October, 10).expect("date"),
            Time::MIDNIGHT,
        );
        KIRO_UPSTREAM_NOW_OVERRIDE.with(|cell| cell.set(Some(now)));
        let failure =
            classify_kiro_upstream_error(400, None, br#"{"reason":"MONTHLY_REQUEST_COUNT"}"#);
        KIRO_UPSTREAM_NOW_OVERRIDE.with(|cell| cell.set(None));
        let envelope: Value =
            serde_json::from_slice(&super::upstream_error_envelope(&failure)).expect("json");
        assert_eq!(envelope["error"]["code"], "quota_exhausted");
        assert_eq!(envelope["error"]["http_status"], 429);
        assert_eq!(envelope["error"]["retry_after_ms"], 1_900_800_000);
        assert_eq!(envelope["error"]["credential_scoped"], true);
        assert_eq!(envelope["error"].get("retryable"), None);
    }

    #[test]
    fn request_body_invalid_omits_retryable_classification_fields() {
        let failure = classify_kiro_upstream_error(
            400,
            None,
            br#"{"reason":"REQUEST_BODY_INVALID","message":"request body is invalid"}"#,
        );
        let envelope: Value =
            serde_json::from_slice(&super::upstream_error_envelope(&failure)).expect("json");
        assert_eq!(envelope["error"]["code"], "upstream_error");
        assert_eq!(envelope["error"]["http_status"], 400);
        assert_eq!(envelope["error"].get("retryable"), None);
        assert_eq!(envelope["error"].get("retry_after_ms"), None);
        assert_eq!(envelope["error"].get("credential_scoped"), None);
        assert!(envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains("REQUEST_BODY_INVALID"));
    }

    #[test]
    fn insufficient_model_capacity_is_retryable_upstream_error() {
        let failure =
            classify_kiro_upstream_error(503, None, br#"{"reason":"INSUFFICIENT_MODEL_CAPACITY"}"#);
        let envelope: Value =
            serde_json::from_slice(&super::upstream_error_envelope(&failure)).expect("json");
        assert_eq!(envelope["error"]["code"], "upstream_error");
        assert_eq!(envelope["error"]["http_status"], 503);
        assert_eq!(envelope["error"]["retryable"], true);
        assert_eq!(envelope["error"].get("credential_scoped"), None);
    }

    #[test]
    fn next_month_start_rolls_over_year() {
        let now = OffsetDateTime::new_utc(
            Date::from_calendar_date(2026, Month::December, 31).expect("date"),
            Time::from_hms(23, 59, 0).expect("time"),
        );
        let got = next_month_start(now);
        assert_eq!(got.year(), 2027);
        assert_eq!(got.month(), Month::January);
        assert_eq!(got.day(), 1);
    }
}
