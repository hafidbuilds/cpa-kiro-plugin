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
#[cfg(test)]
use crate::kiro_event_stream::{ClaudeResponseAccumulator, KiroEvent};
use crate::kiro_request_transform::{translate_claude_request_to_kiro, KiroPayload};

#[path = "kiro-executor-transport.rs"]
mod transport;
use transport::*;
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
        if emitted || !failure.retry_in_plugin() || attempt == MAX_UPSTREAM_ATTEMPTS {
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
                let retryable = error.retry_in_plugin();
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
    // CPA drains the output stream only after `executor.execute_stream` returns,
    // and its bridge buffers just 16 chunks. Pumping the upstream body on the
    // calling thread would block `host.stream.emit` forever, so hand the opened
    // upstream to a worker thread and return the stream headers immediately.
    let output_id = output_id.to_owned();
    let spawned = std::thread::Builder::new()
        .name("kiro-stream".into())
        .spawn(move || pump_kiro_plugin_stream(prepared, first, output_id));
    if let Err(error) = spawned {
        return Ok(plugin_error_envelope(
            "executor_error",
            &format!("start Kiro stream worker: {error}"),
            500,
            true,
            0,
            false,
        ));
    }
    Ok(ok_executor_envelope(
        json!({"headers": {"Content-Type": ["text/event-stream"]}}),
    ))
}

/// Forwards one opened Kiro upstream to the CPA output stream, then closes it.
///
/// Runs on a worker thread; a panic is converted into a stream error instead of
/// unwinding out of the thread.
fn pump_kiro_plugin_stream(
    prepared: PreparedKiroUpstream,
    first: OpenedKiroUpstream,
    output_id: String,
) {
    let mut plugin_stream = PluginStreamClose::new(&output_id);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_kiro_plugin_stream(&prepared, first, &plugin_stream)
    }));
    match outcome {
        Ok(Some(error)) => plugin_stream.fail(error),
        Ok(None) => {}
        Err(_) => plugin_stream.fail("Kiro stream worker panicked"),
    }
    plugin_stream.close();
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
    if retry_after_ms > 0 {
        // CPA's pluginabi.Error reads whole seconds from `retry_after_seconds`;
        // round up so a sub-second hint still delays the retry.
        let seconds = (retry_after_ms + 999) / 1000;
        error.insert("retry_after_seconds".into(), json!(seconds));
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
        assert!(
            !failure.retry_in_plugin(),
            "a 429 must go back to CPA, not be re-sent at once"
        );
        assert_eq!(failure.retry_after_ms, 7000);
        let envelope: Value =
            serde_json::from_slice(&super::upstream_error_envelope(&failure)).expect("json");
        assert_eq!(envelope["error"]["code"], "rate_limited");
        assert_eq!(envelope["error"]["retryable"], true);
        assert_eq!(envelope["error"]["retry_after_seconds"], 7);
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
        assert_eq!(envelope["error"]["retry_after_seconds"], 1_900_800);
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
        assert_eq!(envelope["error"].get("retry_after_seconds"), None);
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
