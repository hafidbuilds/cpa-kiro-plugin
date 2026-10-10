//! CPA method names, registration responses, and native dispatch errors.
use crate::abi::invoke_host_json;
use crate::config::{configure_kiro_plugin, loaded_kiro_config};
use crate::kiro_credentials::{parse_kiro_credential, KiroAuthMethod, KiroCredential};
use crate::kiro_request_transform::translate_claude_request_to_kiro;
use base64::Engine;
use serde_json::{json, Map, Value};
use std::io::Read;
use time::OffsetDateTime;
const OIDC_USER_AGENT: &str =
    "aws-sdk-js/3.714.0 os/macos/24.3.0 lang/js md/nodejs/22.14.0 api/ssooidc/3.714.0 exec-env/kiro-cli/2.7.0 m/E";

/// Structured dispatch failure serialized at the CPA boundary.
pub struct DispatchError {
    /// Stable error code used by CPA.
    pub code: &'static str,
    /// Human-readable error detail.
    pub message: String,
}

/// Dispatches the frozen Go plugin method set supported by the native shell.
pub fn dispatch_method(method: &str, request: &[u8]) -> Result<Vec<u8>, DispatchError> {
    match method {
        "plugin.register" | "plugin.reconfigure" => {
            configure_kiro_plugin(request).map_err(|message| DispatchError {
                code: "invalid_config",
                message,
            })?;
            Ok(ok_envelope(plugin_registration()))
        }
        "model.register" => Ok(ok_envelope(model_registration("configured"))),
        "model.static" => Ok(ok_envelope(model_response("configured"))),
        "model.for_auth" => {
            crate::kiro_models::discover_kiro_models(request).map_err(|message| DispatchError {
                code: "model_discovery_error",
                message,
            })
        }
        "auth.identifier" | "executor.identifier" => Ok(ok_envelope(json!({"identifier": "kiro"}))),
        "auth.parse" => parse_auth_request(request),
        "auth.login.start" => crate::kiro_login::start_kiro_login(request),
        "auth.login.poll" => crate::kiro_login::poll_kiro_login(request),
        "auth.refresh" => refresh_kiro_credential(request),
        "executor.count_tokens" => count_executor_tokens(request),
        "executor.execute" => {
            crate::kiro_executor::execute_kiro_request(request).map_err(|message| DispatchError {
                code: "executor_error",
                message,
            })
        }
        "executor.execute_stream" => crate::kiro_executor::execute_kiro_stream_request(request)
            .map_err(|message| DispatchError {
                code: "executor_error",
                message,
            }),
        "executor.http_request" => crate::kiro_executor::execute_kiro_http_request(request)
            .map_err(|message| DispatchError {
                code: "executor_error",
                message,
            }),
        "command_line.register" => Ok(ok_envelope(
            json!({"Flags": [{"Name": "kiro-login", "Usage": "Login to Kiro in a browser", "Type": "bool"}]}),
        )),
        "command_line.execute" => crate::kiro_login::execute_kiro_command_line(request),
        _ => Err(DispatchError {
            code: "unknown_method",
            message: format!("unknown method: {method}"),
        }),
    }
}

/// Drops process-local device and social login sessions during plugin shutdown.
pub(crate) fn clear_pending_kiro_logins() {
    crate::kiro_login::clear_pending_kiro_logins();
}

pub(super) fn error_envelope(
    code: &str,
    message: impl Into<String>,
    http_status: i64,
    retryable: bool,
) -> Vec<u8> {
    let mut error = Map::new();
    error.insert("code".into(), json!(code));
    error.insert("message".into(), json!(message.into()));
    if http_status != 0 {
        error.insert("http_status".into(), json!(http_status));
    }
    if retryable {
        error.insert("retryable".into(), json!(true));
    }
    serde_json::to_vec(&json!({"ok": false, "error": error})).unwrap_or_else(|_| {
        b"{\"ok\":false,\"error\":{\"code\":\"encode_error\",\"message\":\"failed to encode response\"}}"
            .to_vec()
    })
}

#[derive(Debug)]
pub(super) struct HostHttpResponse {
    pub(super) status: i64,
    pub(super) body: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct HostHttpError {
    pub(super) status: i64,
    pub(super) detail: String,
}

impl std::fmt::Display for HostHttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status == 0 {
            formatter.write_str(&self.detail)
        } else {
            write!(
                formatter,
                "Kiro token refresh failed: HTTP {}: {}",
                self.status, self.detail
            )
        }
    }
}

pub(super) fn post_json(
    callback_id: &str,
    url: &str,
    headers: &Map<String, Value>,
    body: &Value,
) -> Result<Value, HostHttpError> {
    let response = host_http_post(callback_id, url, headers, body)?;
    if !(200..300).contains(&response.status) {
        return Err(HostHttpError {
            status: response.status,
            detail: limited_error_body(&response.body),
        });
    }
    serde_json::from_slice(&response.body).map_err(|error| HostHttpError {
        status: 0,
        detail: format!("decode {} response: {error}", redact_url(url)),
    })
}

pub(super) fn host_http_post(
    callback_id: &str,
    url: &str,
    headers: &Map<String, Value>,
    body: &Value,
) -> Result<HostHttpResponse, HostHttpError> {
    let encoded_body = serde_json::to_vec(body).map_err(|error| HostHttpError {
        status: 0,
        detail: format!("encode {} request: {error}", redact_url(url)),
    })?;
    let callback_request = json!({
        "host_callback_id": callback_id,
        "method": "POST",
        "url": url,
        "headers": headers,
        "body": base64::engine::general_purpose::STANDARD.encode(encoded_body)
    });
    let raw = invoke_host_json(
        "host.http.do",
        &serde_json::to_vec(&callback_request).map_err(|error| HostHttpError {
            status: 0,
            detail: format!("encode {} callback: {error}", redact_url(url)),
        })?,
    )
    .map_err(|message| HostHttpError {
        status: 0,
        detail: format!("call {}: {message}", redact_url(url)),
    })?;
    let response: Value = serde_json::from_slice(&raw).map_err(|error| HostHttpError {
        status: 0,
        detail: format!("decode host HTTP response: {error}"),
    })?;
    let status = response
        .get("StatusCode")
        .or_else(|| response.get("status_code"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let body = match response.get("Body").or_else(|| response.get("body")) {
        Some(Value::String(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap_or_default(),
        Some(Value::Array(bytes)) => bytes
            .iter()
            .filter_map(Value::as_u64)
            .map(|byte| byte as u8)
            .collect(),
        _ => Vec::new(),
    };
    Ok(HostHttpResponse { status, body })
}

pub(super) fn oidc_headers() -> Map<String, Value> {
    let mut headers = oidc_json_headers();
    headers.insert("User-Agent".into(), json!([OIDC_USER_AGENT]));
    headers.insert("Amz-Sdk-Invocation-Id".into(), json!([new_kiro_uuid()]));
    headers.insert("Amz-Sdk-Request".into(), json!(["attempt=1; max=1"]));
    headers
}

pub(super) fn oidc_json_headers() -> Map<String, Value> {
    let mut headers = Map::new();
    headers.insert("Content-Type".into(), json!(["application/json"]));
    headers
}

pub(super) fn profile_list_headers(token: &str, method: KiroAuthMethod) -> Map<String, Value> {
    let mut headers = oidc_json_headers();
    headers.insert("Accept".into(), json!(["application/json"]));
    headers.insert("Authorization".into(), json!([format!("Bearer {token}")]));
    match method {
        KiroAuthMethod::ApiKey => {
            headers.insert("Tokentype".into(), json!(["API_KEY"]));
        }
        KiroAuthMethod::ExternalIdp => {
            headers.insert("Tokentype".into(), json!(["EXTERNAL_IDP"]));
        }
        _ => {}
    }
    headers
}

pub(super) fn oidc_endpoint(region: &str) -> String {
    format!(
        "https://oidc.{}.amazonaws.com",
        if region.is_empty() {
            "us-east-1"
        } else {
            region
        }
    )
}
pub(super) fn fill_random_bytes(buffer: &mut [u8]) {
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        if file.read_exact(buffer).is_ok() {
            return;
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = ((nanos >> ((index % 16) * 8)) as u8).wrapping_add(index as u8);
    }
}

pub(super) fn new_kiro_uuid() -> String {
    let mut bytes = [0_u8; 16];
    fill_random_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub(super) fn format_rfc3339_utc(value: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

pub(super) fn host_callback_id(input: &Value) -> &str {
    input
        .get("host_callback_id")
        .or_else(|| input.get("HostCallbackID"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub(super) fn json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(|value| value.to_owned())
}

pub(super) fn is_https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty() && !host.contains(' ')
}

pub(super) fn query_escape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(byte as char);
            }
            _ => escaped.push_str(&format!("%{byte:02X}")),
        }
    }
    escaped
}

pub(super) fn limited_error_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body).trim().to_owned();
    if text.len() > 1024 {
        text[..1024].to_owned()
    } else {
        text
    }
}

pub(super) fn redact_url(endpoint: &str) -> String {
    if let Some(after_scheme) = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
    {
        let scheme = if endpoint.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        let host = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        let path = after_scheme
            .find('/')
            .map(|index| {
                &after_scheme[index..after_scheme.find(['?', '#']).unwrap_or(after_scheme.len())]
            })
            .unwrap_or("");
        return format!("{scheme}://{host}{path}");
    }
    "upstream endpoint".into()
}

fn decode_storage_field(storage: &Value) -> Result<Vec<u8>, String> {
    match storage {
        Value::String(encoded) => {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if serde_json::from_slice::<Value>(&bytes).is_ok() {
                    return Ok(bytes);
                }
            }
            Ok(encoded.as_bytes().to_vec())
        }
        other => serde_json::to_vec(other).map_err(|error| error.to_string()),
    }
}

fn merge_json_attributes(base: Option<&Value>, overlay: &Value) -> Value {
    let mut merged = Map::new();
    if let Some(Value::Object(base)) = base {
        for (key, value) in base {
            merged.insert(key.clone(), value.clone());
        }
    }
    if let Some(object) = overlay.as_object() {
        for (key, value) in object {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

fn refresh_kiro_credential(request: &[u8]) -> Result<Vec<u8>, DispatchError> {
    let input: Value = serde_json::from_slice(request).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("decode auth refresh request: {error}"),
    })?;
    let Some(storage) = input
        .get("StorageJSON")
        .or_else(|| input.get("storage_json"))
    else {
        return Ok(error_envelope(
            "invalid_auth",
            "Kiro auth refresh request has no StorageJSON",
            0,
            false,
        ));
    };
    let raw_storage = decode_storage_field(storage).map_err(|error| DispatchError {
        code: "invalid_auth",
        message: format!("decode Kiro credential storage: {error}"),
    })?;
    let credential = match parse_kiro_credential(&raw_storage) {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            return Ok(error_envelope(
                "invalid_auth",
                "Kiro auth storage is not recognized",
                0,
                false,
            ))
        }
        Err(error) => return Ok(error_envelope("invalid_auth", error.to_string(), 0, false)),
    };
    let credential = if credential.is_oauth() {
        match refresh_oauth_credential(&input, credential) {
            Ok(credential) => credential,
            Err(error) => return Ok(error),
        }
    } else {
        credential
    };
    let auth_id = json_string(&input, &["AuthID", "auth_id"]).unwrap_or_default();
    let mut auth = credential
        .host_auth_data(&auth_id, "")
        .map_err(|error| DispatchError {
            code: "refresh_failed",
            message: error.to_string(),
        })?;
    if let Some(attributes) = auth.get_mut("Attributes") {
        *attributes = merge_json_attributes(
            input.get("Attributes").or_else(|| input.get("attributes")),
            attributes,
        );
    }
    Ok(ok_envelope(json!({"Auth": auth})))
}

fn refresh_oauth_credential(
    input: &Value,
    mut credential: KiroCredential,
) -> Result<KiroCredential, Vec<u8>> {
    if credential.refresh_token.is_empty() {
        return Err(error_envelope(
            "refresh_failed",
            "Kiro token refresh failed: HTTP 401: credential has no refresh token",
            401,
            false,
        ));
    }
    let callback_id = host_callback_id(input);
    let tokens = match credential.auth_method {
        KiroAuthMethod::Idc => post_json(
            callback_id,
            &format!("{}/token", oidc_endpoint(&credential.region)),
            &oidc_headers(),
            &json!({
                "clientId": credential.client_id,
                "clientSecret": credential.client_secret,
                "refreshToken": credential.refresh_token,
                "grantType": "refresh_token"
            }),
        ),
        KiroAuthMethod::Desktop => {
            let mut headers = oidc_json_headers();
            headers.insert(
                "User-Agent".into(),
                json!(["Kiro-Desktop/0.2.13 (darwin; arm64)"]),
            );
            post_json(
                callback_id,
                &format!(
                    "https://prod.{}.auth.desktop.kiro.dev/refreshToken",
                    if credential.region.is_empty() {
                        "us-east-1"
                    } else {
                        credential.region.as_str()
                    }
                ),
                &headers,
                &json!({"refreshToken": credential.refresh_token}),
            )
        }
        KiroAuthMethod::ExternalIdp => {
            let mut headers = Map::new();
            headers.insert(
                "Content-Type".into(),
                json!(["application/x-www-form-urlencoded"]),
            );
            headers.insert("Accept".into(), json!(["application/json"]));
            let form = format!(
                "grant_type=refresh_token&client_id={}&refresh_token={}",
                query_escape(&credential.client_id),
                query_escape(&credential.refresh_token)
            );
            post_form(
                callback_id,
                &credential.token_endpoint,
                &headers,
                form.as_bytes(),
            )
        }
        KiroAuthMethod::ApiKey => {
            return Err(error_envelope(
                "refresh_failed",
                format!(
                    "unsupported Kiro auth method {:?}",
                    credential.auth_method.as_str()
                ),
                502,
                true,
            ))
        }
    }
    .map_err(refresh_error_envelope)?;
    let access_token = json_string(&tokens, &["accessToken", "access_token"]).unwrap_or_default();
    let refresh_token =
        json_string(&tokens, &["refreshToken", "refresh_token"]).unwrap_or_default();
    let profile_arn = json_string(&tokens, &["profileArn", "profile_arn"]).unwrap_or_default();
    let expires_in = tokens
        .get("expiresIn")
        .or_else(|| tokens.get("expires_in"))
        .and_then(Value::as_i64)
        .unwrap_or_default();
    credential
        .apply_oauth_tokens(&access_token, &refresh_token, expires_in, &profile_arn)
        .map_err(|error| error_envelope("refresh_failed", error.to_string(), 502, true))?;
    Ok(credential)
}

fn refresh_error_envelope(error: HostHttpError) -> Vec<u8> {
    if error.status != 0 {
        error_envelope("refresh_failed", error.to_string(), error.status, false)
    } else {
        error_envelope("refresh_failed", error.to_string(), 502, true)
    }
}

fn post_form(
    callback_id: &str,
    url: &str,
    headers: &Map<String, Value>,
    body: &[u8],
) -> Result<Value, HostHttpError> {
    let callback_request = json!({
        "host_callback_id": callback_id,
        "method": "POST",
        "url": url,
        "headers": headers,
        "body": base64::engine::general_purpose::STANDARD.encode(body)
    });
    let raw = invoke_host_json(
        "host.http.do",
        &serde_json::to_vec(&callback_request).map_err(|error| HostHttpError {
            status: 0,
            detail: format!("encode {} callback: {error}", redact_url(url)),
        })?,
    )
    .map_err(|message| HostHttpError {
        status: 0,
        detail: format!("call {}: {message}", redact_url(url)),
    })?;
    let response: Value = serde_json::from_slice(&raw).map_err(|error| HostHttpError {
        status: 0,
        detail: format!("decode host HTTP response: {error}"),
    })?;
    let status = response
        .get("StatusCode")
        .or_else(|| response.get("status_code"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let body = match response.get("Body").or_else(|| response.get("body")) {
        Some(Value::String(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    if !(200..300).contains(&status) {
        return Err(HostHttpError {
            status,
            detail: limited_error_body(&body),
        });
    }
    serde_json::from_slice(&body).map_err(|error| HostHttpError {
        status: 0,
        detail: format!("decode {} response: {error}", redact_url(url)),
    })
}

fn parse_auth_request(request: &[u8]) -> Result<Vec<u8>, DispatchError> {
    let input: Value = serde_json::from_slice(request).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("decode auth parse request: {error}"),
    })?;
    let Some(storage) = input
        .get("RawJSON")
        .or_else(|| input.get("raw_json"))
        .or_else(|| input.get("storage_json"))
        .or_else(|| input.get("StorageJSON"))
    else {
        return Ok(ok_envelope(json!({"Handled": false})));
    };
    let raw_storage = decode_storage_field(storage).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("decode auth storage: {error}"),
    })?;
    let credential = match parse_kiro_credential(&raw_storage) {
        Ok(Some(credential)) => credential,
        Ok(None) => return Ok(ok_envelope(json!({"Handled": false}))),
        Err(error) => return Ok(error_envelope("invalid_auth", error.to_string(), 0, false)),
    };
    let file_name = json_string(&input, &["FileName", "file_name"]).unwrap_or_default();
    let auth_id = if file_name.trim().is_empty() {
        format!("kiro-{}", credential.fingerprint())
    } else {
        file_name.trim().to_owned()
    };
    let auth = credential
        .host_auth_data(&auth_id, &file_name)
        .map_err(|error| DispatchError {
            code: "invalid_auth",
            message: error.to_string(),
        })?;
    Ok(ok_envelope(json!({"Handled": true, "Auth": auth})))
}

fn count_executor_tokens(request: &[u8]) -> Result<Vec<u8>, DispatchError> {
    let input: Value = serde_json::from_slice(request).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("decode executor request: {error}"),
    })?;
    let payload = input
        .get("payload")
        .and_then(Value::as_str)
        .unwrap_or_default();
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|error| DispatchError {
            code: "invalid_request",
            message: format!("decode Claude token-count request: {error}"),
        })?;
    let (_, decoded_request) =
        translate_claude_request_to_kiro(&payload, "").map_err(|error| DispatchError {
            code: "invalid_request",
            message: format!("invalid Claude token-count request: {error}"),
        })?;
    let serialized = serde_json::to_string(&decoded_request).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("encode token-count request: {error}"),
    })?;
    let estimate = serialized.chars().count().div_ceil(4);
    Ok(ok_envelope(json!({
        "Payload": base64::engine::general_purpose::STANDARD.encode(format!(r#"{{"input_tokens":{estimate}}}"#)),
        "Headers": {"Content-Type": ["application/json"]},
        "Metadata": {"estimated": true}
    })))
}

pub(super) fn ok_envelope(value: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok": true, "result": value})).unwrap_or_else(|_| b"{\"ok\":false,\"error\":{\"code\":\"encode_error\",\"message\":\"failed to encode response\"}}".to_vec())
}

fn plugin_registration() -> Value {
    json!({
        "schema_version": 6,
        "metadata": {
            "Name": "kiro", "Version": "0.1.0", "Author": "router-for-me",
            "GitHubRepository": "https://github.com/router-for-me/CLIProxyAPI",
            "ConfigFields": [
                {"Name": "models", "Type": "array", "Description": "Allowed Kiro model IDs. Use * to expose every model discovered for an account."},
                {"Name": "kiro_version", "Type": "string", "Description": "Kiro client version sent in upstream compatibility headers."},
                {"Name": "node_version", "Type": "string", "Description": "Node.js version sent in upstream compatibility headers."},
                {"Name": "system_version", "Type": "string", "Description": "Operating-system version sent in upstream compatibility headers."}
            ]
        },
        "capabilities": {
            "model_registrar": true, "model_provider": true, "auth_provider": true,
            "executor": true, "executor_model_scope": "both",
            "executor_input_formats": ["claude"], "executor_output_formats": ["claude"],
            "command_line_plugin": true
        }
    })
}

fn model_registration(mode: &str) -> Value {
    json!({"Provider": "kiro", "Models": configured_model_values(mode)})
}

fn model_response(mode: &str) -> Value {
    json!({"Provider": "kiro", "Models": configured_model_values(mode)})
}

fn configured_model_values(_mode: &str) -> Vec<Value> {
    let config = loaded_kiro_config();
    let models = if config.models.iter().any(|model| model == "*") {
        KiroPluginConfigModels::default_models()
    } else {
        config.models
    };
    models.into_iter().map(|model| json!({
        "ID": model, "Name": model, "DisplayName": model, "Object": "model", "OwnedBy": "kiro", "Type": "claude",
        "ContextLength": 200000, "InputTokenLimit": 200000, "OutputTokenLimit": 64000, "MaxCompletionTokens": 64000,
        "SupportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        "SupportedParameters": ["max_tokens", "temperature", "top_p", "tools"],
        "SupportedInputModalities": ["text", "image"], "SupportedOutputModalities": ["text"]
    })).collect()
}

struct KiroPluginConfigModels;
impl KiroPluginConfigModels {
    fn default_models() -> Vec<String> {
        vec!["claude-sonnet-4.5".into(), "claude-haiku-4.5".into()]
    }
}
