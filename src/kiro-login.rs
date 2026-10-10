//! Kiro login, device login, and social login flows.
use crate::dispatch::{
    error_envelope, fill_random_bytes, format_rfc3339_utc, host_callback_id, host_http_post,
    is_https_url, json_string, oidc_endpoint, oidc_headers, ok_envelope, post_json,
    profile_list_headers, query_escape, DispatchError, HostHttpError,
};
use crate::kiro_credentials::{
    api_region, candidate_management_regions, is_valid_kiro_region, region_from_profile_arn,
    KiroAuthMethod, KiroCredential, BUILDER_ID_PROFILE_ARN, BUILDER_ID_START_URL,
    KIRO_MANAGEMENT_REGIONS, KIRO_PLUGIN_IDENTIFIER,
};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use time::{Duration as TimeDuration, OffsetDateTime};
const LOGIN_METHOD_BUILDER_ID: &str = "builder-id";
const LOGIN_METHOD_IDC: &str = "idc";
const DEVICE_LOGIN_FALLBACK_TTL: Duration = Duration::from_secs(10 * 60);
const DEFAULT_DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(5);
const SLOW_DOWN_BACKOFF: Duration = Duration::from_secs(5);
const SOCIAL_LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
const SOCIAL_REDIRECT_URI: &str = "http://localhost:3128";
const SOCIAL_CALLBACK_PATH: &str = "/oauth/callback";
const KIRO_SIGN_IN_URL: &str = "https://app.kiro.dev/signin";
const OIDC_SCOPES: [&str; 5] = [
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
    "codewhisperer:transformations",
    "codewhisperer:taskassist",
];

static PENDING_DEVICE_LOGINS: LazyLock<Mutex<HashMap<String, PendingDeviceLogin>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PENDING_SOCIAL_LOGINS: LazyLock<Mutex<HashMap<String, PendingSocialLogin>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LOGIN_STATE_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut key = [0_u8; 32];
    fill_random_bytes(&mut key);
    key
});

#[derive(Clone)]
struct PendingDeviceLogin {
    method: String,
    region: String,
    start_url: String,
    client_id: String,
    client_secret: String,
    device_code: String,
    interval: Duration,
    next_poll_at: Instant,
    expires_at: Instant,
}

#[derive(Clone)]
struct PendingSocialLogin {
    code_verifier: String,
    login_option: String,
    expires_at: Instant,
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; BLOCK];
    let mut opad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = Sha256::digest(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    Sha256::digest(&outer).into()
}

fn new_login_state() -> String {
    let mut nonce = [0_u8; 16];
    fill_random_bytes(&mut nonce);
    let mac = hmac_sha256(&*LOGIN_STATE_KEY, &nonce);
    let mut token = Vec::with_capacity(24);
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&mac[..8]);
    format!(
        "kiro-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
    )
}
fn metadata_string<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    let metadata = input.get("metadata").or_else(|| input.get("Metadata"))?;
    match metadata.get(key) {
        Some(Value::String(value)) => Some(value.as_str()),
        Some(Value::Array(values)) => values.first().and_then(Value::as_str),
        _ => None,
    }
}
pub(crate) fn execute_kiro_command_line(request: &[u8]) -> Result<Vec<u8>, DispatchError> {
    let input: Value = serde_json::from_slice(request).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("decode Kiro command-line request: {error}"),
    })?;
    let triggered = input
        .get("TriggeredFlags")
        .or_else(|| input.get("triggered_flags"));
    let login_requested = triggered
        .and_then(Value::as_object)
        .and_then(|flags| flags.get("kiro-login"))
        .and_then(|flag| flag.get("Set").or_else(|| flag.get("set")))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !login_requested {
        return Ok(ok_envelope(json!({
            "Stdout": base64::engine::general_purpose::STANDARD.encode([]),
            "Stderr": base64::engine::general_purpose::STANDARD.encode([]),
            "ExitCode": 0
        })));
    }
    let host = input
        .get("Host")
        .or_else(|| input.get("host"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let auth_dir = host
        .get("AuthDir")
        .or_else(|| host.get("auth_dir"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned();
    if auth_dir.is_empty() {
        return command_line_error("CLIProxyAPI did not provide an auth directory");
    }
    fs::create_dir_all(&auth_dir).map_err(|error| DispatchError {
        code: "login_failed",
        message: format!("create Kiro auth directory: {error}"),
    })?;
    let start_request = json!({
        "Provider": KIRO_PLUGIN_IDENTIFIER, "Host": host, "Metadata": {"method": "social"}
    });
    let start_raw =
        start_kiro_login(
            &serde_json::to_vec(&start_request).map_err(|error| DispatchError {
                code: "login_failed",
                message: format!("encode Kiro login request: {error}"),
            })?,
        )?;
    let start = serde_json::from_slice::<Value>(&start_raw)
        .ok()
        .and_then(|response| response.get("result").cloned())
        .ok_or_else(|| DispatchError {
            code: "login_failed",
            message: "decode Kiro login start response".into(),
        })?;
    let state = json_string(&start, &["State", "state"]).unwrap_or_default();
    let login_url = json_string(&start, &["URL", "url"]).unwrap_or_default();
    if state.is_empty() || login_url.is_empty() {
        return command_line_error("Kiro login did not return a browser URL");
    }
    let callback = start_kiro_callback_listener(Path::new(&auth_dir), &state)?;
    let mut stdout = format!("Kiro login started.\nLogin URL: {login_url}\n");
    if let Err(error) = open_kiro_login_url(&login_url) {
        stdout.push_str(&format!("Open the URL above in a browser: {error}\n"));
    }
    let poll_request = json!({"Provider": KIRO_PLUGIN_IDENTIFIER, "State": state, "Host": host});
    let deadline = Instant::now() + SOCIAL_LOGIN_TTL;
    while Instant::now() < deadline {
        let poll_raw = poll_kiro_login(&serde_json::to_vec(&poll_request).map_err(|error| {
            DispatchError {
                code: "login_failed",
                message: format!("encode Kiro login poll request: {error}"),
            }
        })?)?;
        let poll = serde_json::from_slice::<Value>(&poll_raw).map_err(|error| DispatchError {
            code: "login_failed",
            message: format!("decode Kiro login poll response: {error}"),
        })?;
        let result = poll.get("result").cloned().unwrap_or_default();
        match json_string(&result, &["Status", "status"])
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "success" => {
                let Some(auth) = result.get("Auth").or_else(|| result.get("auth")).cloned() else {
                    return command_line_error("Kiro login succeeded without credentials");
                };
                let _ = callback.join();
                return Ok(ok_envelope(json!({
                    "Stdout": base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
                    "Stderr": base64::engine::general_purpose::STANDARD.encode([]),
                    "Auths": [auth],
                    "ExitCode": 0
                })));
            }
            "pending" => thread::sleep(Duration::from_secs(1)),
            _ => {
                let message = json_string(&result, &["Message", "message"])
                    .unwrap_or_else(|| "Kiro login failed".into());
                return Ok(ok_envelope(json!({
                    "Stdout": base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
                    "Stderr": base64::engine::general_purpose::STANDARD.encode(format!("{message}\n").as_bytes()),
                    "ExitCode": 1
                })));
            }
        }
    }
    let _ = callback.join();
    Ok(ok_envelope(json!({
        "Stdout": base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        "Stderr": base64::engine::general_purpose::STANDARD.encode([]),
        "ExitCode": 1
    })))
}

fn command_line_error(message: &str) -> Result<Vec<u8>, DispatchError> {
    Ok(ok_envelope(json!({
        "Stdout": base64::engine::general_purpose::STANDARD.encode([]),
        "Stderr": base64::engine::general_purpose::STANDARD.encode(format!("{message}\n").as_bytes()),
        "ExitCode": 1
    })))
}

fn open_kiro_login_url(url: &str) -> Result<(), String> {
    let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "linux") {
        ("xdg-open", vec![url])
    } else if cfg!(target_os = "windows") {
        ("rundll32", vec!["url.dll,FileProtocolHandler", url])
    } else {
        return Err(format!(
            "automatic browser launch is not supported on {}",
            std::env::consts::OS
        ));
    };
    Command::new(program)
        .args(args)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("launch browser: {error}"))
}

fn start_kiro_callback_listener(
    auth_dir: &Path,
    state: &str,
) -> Result<thread::JoinHandle<()>, DispatchError> {
    let listener = TcpListener::bind("127.0.0.1:3128").map_err(|error| DispatchError {
        code: "login_failed",
        message: format!("listen for Kiro sign-in callback on 127.0.0.1:3128: {error}"),
    })?;
    let callback_path = auth_dir.join(format!(".oauth-kiro-{state}.oauth"));
    let state = state.to_owned();
    Ok(thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0_u8; 8192];
            let length = stream.read(&mut request).unwrap_or_default();
            let request = String::from_utf8_lossy(&request[..length]);
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            let query = target.split_once('?').map_or("", |(_, query)| query);
            let callback_state = query_parameter(query, "state");
            if callback_state == state {
                let body = serde_json::to_vec(&json!({
                    "code": query_parameter(query, "code"),
                    "state": callback_state,
                    "error": query_parameter(query, "error"),
                    "login_option": query_parameter(query, "login_option")
                }));
                if let Ok(body) = body {
                    let _ = fs::write(callback_path, body);
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKiro login callback received. Return to the terminal.\n");
                }
            }
        }
    }))
}

fn query_parameter(query: &str, key: &str) -> String {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| percent_decode(value))
        .unwrap_or_default()
}

fn percent_decode(value: &str) -> String {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(decoded) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                output.push(decoded);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}
pub(crate) fn start_kiro_login(request: &[u8]) -> Result<Vec<u8>, DispatchError> {
    let input: Value = serde_json::from_slice(request).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("decode login start request: {error}"),
    })?;
    let method = metadata_string(&input, "method")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match method.as_str() {
        "" | LOGIN_METHOD_BUILDER_ID => start_device_login(
            host_callback_id(&input),
            LOGIN_METHOD_BUILDER_ID,
            BUILDER_ID_START_URL,
            "us-east-1",
        ),
        LOGIN_METHOD_IDC => {
            let start_url = metadata_string(&input, "start_url").unwrap_or_default();
            if !is_https_url(start_url.trim()) {
                return Ok(error_envelope(
                    "invalid_request",
                    "idc login requires an https start_url query parameter",
                    400,
                    false,
                ));
            }
            let region = metadata_string(&input, "region")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if !is_valid_kiro_region(&region) {
                return Ok(error_envelope(
                    "invalid_request",
                    "idc login requires the Identity Center region query parameter",
                    400,
                    false,
                ));
            }
            start_device_login(
                host_callback_id(&input),
                LOGIN_METHOD_IDC,
                start_url.trim(),
                &region,
            )
        }
        "github" | "google" | "social" => {
            let login_option = if method == "social" {
                String::new()
            } else {
                method
            };
            start_social_login(&login_option)
        }
        other => Ok(error_envelope(
            "invalid_request",
            format!(
                "unsupported Kiro login method {other:?}; use builder-id, idc, github, google, or social"
            ),
            400,
            false,
        )),
    }
}

fn start_device_login(
    callback_id: &str,
    method: &str,
    start_url: &str,
    region: &str,
) -> Result<Vec<u8>, DispatchError> {
    let oidc_base = oidc_endpoint(region);
    let registration = match post_json(
        callback_id,
        &format!("{oidc_base}/client/register"),
        &oidc_headers(),
        &json!({
            "clientName": "Kiro CLI",
            "clientType": "public",
            "scopes": OIDC_SCOPES,
            "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"]
        }),
    ) {
        Ok(value) => value,
        Err(error) => return Ok(login_error_envelope("register Kiro OIDC client", &error)),
    };
    let client_id = json_string(&registration, &["clientId"]).unwrap_or_default();
    let client_secret = json_string(&registration, &["clientSecret"]).unwrap_or_default();
    if client_id.is_empty() || client_secret.is_empty() {
        return Ok(error_envelope(
            "login_failed",
            "Kiro OIDC client registration returned no client credentials",
            502,
            true,
        ));
    }
    let device = match post_json(
        callback_id,
        &format!("{oidc_base}/device_authorization"),
        &oidc_headers(),
        &json!({
            "clientId": client_id,
            "clientSecret": client_secret,
            "startUrl": start_url
        }),
    ) {
        Ok(value) => value,
        Err(error) => {
            return Ok(login_error_envelope(
                "start Kiro device authorization",
                &error,
            ))
        }
    };
    let verification_url = json_string(
        &device,
        &["verificationUriComplete", "verification_uri_complete"],
    )
    .unwrap_or_default();
    let device_code = json_string(&device, &["deviceCode", "device_code"]).unwrap_or_default();
    let user_code = json_string(&device, &["userCode", "user_code"]).unwrap_or_default();
    if verification_url.is_empty() || device_code.is_empty() {
        return Ok(error_envelope(
            "login_failed",
            "Kiro device authorization returned no device code",
            502,
            true,
        ));
    }
    let interval_secs = device
        .get("interval")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let interval = if interval_secs > 0 {
        Duration::from_secs(interval_secs as u64)
    } else {
        DEFAULT_DEVICE_POLL_INTERVAL
    };
    let ttl_secs = device
        .get("expiresIn")
        .or_else(|| device.get("expires_in"))
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let ttl = if ttl_secs > 0 {
        Duration::from_secs(ttl_secs as u64)
    } else {
        DEVICE_LOGIN_FALLBACK_TTL
    };
    let now = Instant::now();
    let state = new_login_state();
    let pending = PendingDeviceLogin {
        method: method.to_owned(),
        region: region.to_owned(),
        start_url: start_url.to_owned(),
        client_id,
        client_secret,
        device_code,
        interval,
        next_poll_at: now + interval,
        expires_at: now + ttl,
    };
    store_pending_device_login(state.clone(), pending, now)?;
    let expires_at =
        format_rfc3339_utc(OffsetDateTime::now_utc() + TimeDuration::seconds(ttl.as_secs() as i64));
    Ok(ok_envelope(json!({
        "Provider": KIRO_PLUGIN_IDENTIFIER,
        "URL": verification_url,
        "State": state,
        "ExpiresAt": expires_at,
        "Metadata": {"flow": "device", "user_code": user_code}
    })))
}

fn start_social_login(login_option: &str) -> Result<Vec<u8>, DispatchError> {
    let mut verifier_bytes = [0_u8; 32];
    fill_random_bytes(&mut verifier_bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let state = new_login_state();
    let mut query = vec![
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_owned()),
        ("redirect_from", "kirocli".to_owned()),
        ("redirect_uri", SOCIAL_REDIRECT_URI.to_owned()),
        ("state", state.clone()),
    ];
    if !login_option.is_empty() {
        query.push(("login_option", login_option.to_owned()));
    }
    query.sort_by(|left, right| left.0.cmp(right.0));
    let encoded: Vec<String> = query
        .into_iter()
        .map(|(key, value)| format!("{key}={}", query_escape(&value)))
        .collect();
    let now = Instant::now();
    store_pending_social_login(
        state.clone(),
        PendingSocialLogin {
            code_verifier: verifier,
            login_option: login_option.to_owned(),
            expires_at: now + SOCIAL_LOGIN_TTL,
        },
        now,
    )?;
    let expires_at = format_rfc3339_utc(
        OffsetDateTime::now_utc() + TimeDuration::seconds(SOCIAL_LOGIN_TTL.as_secs() as i64),
    );
    Ok(ok_envelope(json!({
        "Provider": KIRO_PLUGIN_IDENTIFIER,
        "URL": format!("{KIRO_SIGN_IN_URL}?{}", encoded.join("&")),
        "State": state,
        "ExpiresAt": expires_at,
        "Metadata": {
            "flow": "social",
            "callback": "submit the localhost:3128 redirect URL to /v8/management/oauth/callback"
        }
    })))
}

pub(crate) fn poll_kiro_login(request: &[u8]) -> Result<Vec<u8>, DispatchError> {
    let input: Value = serde_json::from_slice(request).map_err(|error| DispatchError {
        code: "invalid_request",
        message: format!("decode login poll request: {error}"),
    })?;
    if let Some(response) = poll_social_login(&input)? {
        return Ok(response);
    }
    let state = json_string(&input, &["State", "state"]).unwrap_or_default();
    let callback_id = host_callback_id(&input);
    let now = Instant::now();
    let pending = {
        let mut pending_logins = PENDING_DEVICE_LOGINS.lock().map_err(|_| DispatchError {
            code: "login_failed",
            message: "Kiro login state lock poisoned".into(),
        })?;
        let mut exists = pending_logins.contains_key(&state);
        if exists
            && pending_logins
                .get(&state)
                .is_some_and(|stored| now > stored.expires_at)
        {
            pending_logins.remove(&state);
            exists = false;
        }
        if !exists {
            return Ok(poll_error_response(
                "Kiro login session expired or is unknown; start a new login",
            ));
        }
        let ready = pending_logins
            .get(&state)
            .is_some_and(|stored| now >= stored.next_poll_at);
        if !ready {
            return Ok(poll_pending_response());
        }
        if let Some(stored) = pending_logins.get_mut(&state) {
            stored.next_poll_at = now + stored.interval;
            Some(stored.clone())
        } else {
            None
        }
    };
    let Some(pending) = pending else {
        return Ok(poll_pending_response());
    };

    let token_body = json!({
        "clientId": pending.client_id,
        "clientSecret": pending.client_secret,
        "deviceCode": pending.device_code,
        "grantType": "urn:ietf:params:oauth:grant-type:device_code"
    });
    let response = match host_http_post(
        callback_id,
        &format!("{}/token", oidc_endpoint(&pending.region)),
        &oidc_headers(),
        &token_body,
    ) {
        Ok(response) => response,
        Err(_) => return Ok(poll_pending_response()),
    };
    if !(200..300).contains(&response.status) {
        let oidc_error = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|body| json_string(&body, &["error"]))
            .unwrap_or_default();
        match oidc_error.as_str() {
            "authorization_pending" => return Ok(poll_pending_response()),
            "slow_down" => {
                if let Ok(mut pending_logins) = PENDING_DEVICE_LOGINS.lock() {
                    if let Some(current) = pending_logins.get_mut(&state) {
                        current.interval += SLOW_DOWN_BACKOFF;
                        current.next_poll_at = Instant::now() + current.interval;
                    }
                }
                return Ok(poll_pending_response());
            }
            _ => {
                finish_device_login(&state);
                let reason = if oidc_error.is_empty() {
                    format!("HTTP {}", response.status)
                } else {
                    oidc_error
                };
                return Ok(poll_error_response(format!(
                    "Kiro device authorization failed: {reason}"
                )));
            }
        }
    }
    let token: Value = match serde_json::from_slice(&response.body) {
        Ok(value) => value,
        Err(_) => {
            finish_device_login(&state);
            return Ok(poll_error_response(
                "Kiro device authorization returned no tokens",
            ));
        }
    };
    let access_token = json_string(&token, &["accessToken", "access_token"]).unwrap_or_default();
    let refresh_token = json_string(&token, &["refreshToken", "refresh_token"]).unwrap_or_default();
    if access_token.is_empty() || refresh_token.is_empty() {
        finish_device_login(&state);
        return Ok(poll_error_response(
            "Kiro device authorization returned no tokens",
        ));
    }
    finish_device_login(&state);
    let expires_in = token
        .get("expiresIn")
        .or_else(|| token.get("expires_in"))
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let mut credential = KiroCredential {
        credential_type: KIRO_PLUGIN_IDENTIFIER.to_owned(),
        auth_method: KiroAuthMethod::Idc,
        region: pending.region.clone(),
        client_id: pending.client_id,
        client_secret: pending.client_secret,
        start_url: pending.start_url,
        ..KiroCredential::default()
    };
    if let Err(error) = credential.apply_oauth_tokens(&access_token, &refresh_token, expires_in, "")
    {
        return Ok(poll_error_response(error.to_string()));
    }
    match pending.method.as_str() {
        LOGIN_METHOD_BUILDER_ID => credential.profile_arn = BUILDER_ID_PROFILE_ARN.to_owned(),
        LOGIN_METHOD_IDC => match discover_profile_arn(callback_id, &credential) {
            Ok(profile_arn) => credential.profile_arn = profile_arn,
            Err(error) => {
                return Ok(poll_error_response(format!(
                    "Kiro login succeeded but no profile was found: {error}"
                )))
            }
        },
        other => {
            return Ok(poll_error_response(format!(
                "unsupported Kiro login method {other:?}"
            )))
        }
    }
    let file_name = credential.credential_file_name();
    let auth = credential
        .host_auth_data(&file_name, &file_name)
        .map_err(|error| DispatchError {
            code: "login_failed",
            message: error.to_string(),
        })?;
    Ok(ok_envelope(json!({"Status": "success", "Auth": auth})))
}

fn poll_social_login(input: &Value) -> Result<Option<Vec<u8>>, DispatchError> {
    let state = json_string(input, &["State", "state"]).unwrap_or_default();
    let now = Instant::now();
    let pending = {
        let mut pending_logins = PENDING_SOCIAL_LOGINS.lock().map_err(|_| DispatchError {
            code: "login_failed",
            message: "Kiro login state lock poisoned".into(),
        })?;
        match pending_logins.get(&state) {
            None => return Ok(None),
            Some(stored) if now > stored.expires_at => {
                pending_logins.remove(&state);
                None
            }
            Some(stored) => Some(stored.clone()),
        }
    };
    let Some(pending) = pending else {
        return Ok(Some(poll_error_response(
            "Kiro login session expired; start a new login",
        )));
    };
    let auth_dir = input
        .pointer("/Host/AuthDir")
        .or_else(|| input.pointer("/host/auth_dir"))
        .or_else(|| input.pointer("/Host/auth_dir"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned();
    let callback = match read_oauth_callback_file(&auth_dir, &state) {
        Ok(Some(callback)) => callback,
        Ok(None) => return Ok(Some(poll_pending_response())),
        Err(message) => {
            finish_social_login(&state);
            return Ok(Some(poll_error_response(message)));
        }
    };
    finish_social_login(&state);
    if let Some(error) = callback
        .get("error")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(poll_error_response(format!(
            "Kiro sign-in failed: {error}"
        ))));
    }
    let callback_state = json_string(&callback, &["state", "State"]).unwrap_or_default();
    let code = json_string(&callback, &["code", "Code"]).unwrap_or_default();
    if callback_state != state || code.is_empty() {
        return Ok(Some(poll_error_response(
            "Kiro sign-in callback did not match this login",
        )));
    }
    let callback_login_option =
        json_string(&callback, &["login_option", "LoginOption"]).unwrap_or_default();
    let pending = if pending.login_option.is_empty() && !callback_login_option.is_empty() {
        PendingSocialLogin {
            login_option: callback_login_option,
            ..pending
        }
    } else {
        pending
    };
    match exchange_social_code(host_callback_id(input), &code, &pending) {
        Ok(credential) => {
            let file_name = credential.credential_file_name();
            let auth = credential
                .host_auth_data(&file_name, &file_name)
                .map_err(|error| DispatchError {
                    code: "login_failed",
                    message: error.to_string(),
                })?;
            Ok(Some(ok_envelope(
                json!({"Status": "success", "Auth": auth}),
            )))
        }
        Err(message) => Ok(Some(poll_error_response(message))),
    }
}

fn social_token_redirect_uri(login_option: &str) -> String {
    let mut redirect_uri = format!("{SOCIAL_REDIRECT_URI}{SOCIAL_CALLBACK_PATH}");
    if !login_option.is_empty() {
        redirect_uri.push_str("?login_option=");
        redirect_uri.push_str(&query_escape(login_option));
    }
    redirect_uri
}

fn exchange_social_code(
    callback_id: &str,
    code: &str,
    pending: &PendingSocialLogin,
) -> Result<KiroCredential, String> {
    let redirect_uri = social_token_redirect_uri(&pending.login_option);
    let token = post_json(
        callback_id,
        "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token",
        &oidc_headers(),
        &json!({
            "code": code,
            "code_verifier": pending.code_verifier,
            "redirect_uri": redirect_uri
        }),
    )
    .map_err(|error| format!("exchange Kiro sign-in code: {error}"))?;
    let access_token = json_string(&token, &["accessToken", "access_token"]).unwrap_or_default();
    let refresh_token = json_string(&token, &["refreshToken", "refresh_token"]).unwrap_or_default();
    if refresh_token.is_empty() {
        return Err("Kiro sign-in returned no refresh token".into());
    }
    let expires_in = token
        .get("expiresIn")
        .or_else(|| token.get("expires_in"))
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let profile_arn = json_string(&token, &["profileArn", "profile_arn"]).unwrap_or_default();
    let mut credential = KiroCredential {
        credential_type: KIRO_PLUGIN_IDENTIFIER.to_owned(),
        auth_method: KiroAuthMethod::Desktop,
        region: "us-east-1".into(),
        ..KiroCredential::default()
    };
    credential
        .apply_oauth_tokens(&access_token, &refresh_token, expires_in, &profile_arn)
        .map_err(|error| error.to_string())?;
    if credential.profile_arn.is_empty() {
        credential.profile_arn = discover_profile_arn(callback_id, &credential)
            .map_err(|error| format!("Kiro sign-in succeeded but no profile was found: {error}"))?;
    }
    Ok(credential)
}

fn read_oauth_callback_file(auth_dir: &str, state: &str) -> Result<Option<Value>, String> {
    if auth_dir.is_empty() {
        return Err("host did not provide an auth directory for the Kiro sign-in callback".into());
    }
    let path = std::path::Path::new(auth_dir).join(format!(".oauth-kiro-{state}.oauth"));
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read Kiro sign-in callback: {error}")),
    };
    let _ = std::fs::remove_file(path);
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|error| format!("decode Kiro sign-in callback: {error}"))
}

fn discover_profile_arn(callback_id: &str, credential: &KiroCredential) -> Result<String, String> {
    let token = credential
        .bearer_token()
        .map_err(|error| error.to_string())?;
    let mut last_forbidden = None;
    for region in candidate_management_regions(api_region(&credential.region)) {
        match post_json(
            callback_id,
            &format!("https://management.{region}.kiro.dev/List-Available-Profiles"),
            &profile_list_headers(&token, credential.auth_method),
            &json!({}),
        ) {
            Ok(response) => {
                if let Some(profiles) = response.get("profiles").and_then(Value::as_array) {
                    for profile in profiles {
                        if let Some(arn) = profile.get("arn").and_then(Value::as_str) {
                            if region_from_profile_arn(arn).is_some() {
                                return Ok(arn.to_owned());
                            }
                        }
                    }
                }
            }
            Err(error) if error.status == 403 => last_forbidden = Some(error),
            Err(error) => return Err(error.to_string()),
        }
    }
    if let Some(error) = last_forbidden {
        return Err(error.to_string());
    }
    Err(format!(
        "no Kiro profile listed in [{}]",
        KIRO_MANAGEMENT_REGIONS.join(" ")
    ))
}

fn finish_device_login(state: &str) {
    if let Ok(mut pending) = PENDING_DEVICE_LOGINS.lock() {
        pending.remove(state);
    }
}

fn finish_social_login(state: &str) {
    if let Ok(mut pending) = PENDING_SOCIAL_LOGINS.lock() {
        pending.remove(state);
    }
}

fn store_pending_device_login(
    state: String,
    pending: PendingDeviceLogin,
    now: Instant,
) -> Result<(), DispatchError> {
    let mut device = PENDING_DEVICE_LOGINS.lock().map_err(|_| DispatchError {
        code: "login_failed",
        message: "Kiro login state lock poisoned".into(),
    })?;
    let mut social = PENDING_SOCIAL_LOGINS.lock().map_err(|_| DispatchError {
        code: "login_failed",
        message: "Kiro login state lock poisoned".into(),
    })?;
    prune_expired_logins_locked(&mut device, &mut social, now);
    device.insert(state, pending);
    Ok(())
}

fn store_pending_social_login(
    state: String,
    pending: PendingSocialLogin,
    now: Instant,
) -> Result<(), DispatchError> {
    let mut device = PENDING_DEVICE_LOGINS.lock().map_err(|_| DispatchError {
        code: "login_failed",
        message: "Kiro login state lock poisoned".into(),
    })?;
    let mut social = PENDING_SOCIAL_LOGINS.lock().map_err(|_| DispatchError {
        code: "login_failed",
        message: "Kiro login state lock poisoned".into(),
    })?;
    prune_expired_logins_locked(&mut device, &mut social, now);
    social.insert(state, pending);
    Ok(())
}

fn prune_expired_logins_locked(
    device: &mut HashMap<String, PendingDeviceLogin>,
    social: &mut HashMap<String, PendingSocialLogin>,
    now: Instant,
) {
    device.retain(|_, pending| now <= pending.expires_at);
    social.retain(|_, pending| now <= pending.expires_at);
}

/// Drops process-local device and social login sessions during plugin shutdown.
pub(crate) fn clear_pending_kiro_logins() {
    if let Ok(mut pending) = PENDING_DEVICE_LOGINS.lock() {
        pending.clear();
    }
    if let Ok(mut pending) = PENDING_SOCIAL_LOGINS.lock() {
        pending.clear();
    }
}

fn poll_pending_response() -> Vec<u8> {
    ok_envelope(json!({"Status": "pending"}))
}

fn poll_error_response(message: impl Into<String>) -> Vec<u8> {
    ok_envelope(json!({"Status": "error", "Message": message.into()}))
}

fn login_error_envelope(action: &str, error: &HostHttpError) -> Vec<u8> {
    if (400..500).contains(&error.status) {
        error_envelope(
            "login_failed",
            format!("{action}: {error}"),
            error.status,
            false,
        )
    } else {
        error_envelope("login_failed", format!("{action}: {error}"), 502, true)
    }
}

#[cfg(test)]
mod tests {
    use super::social_token_redirect_uri;

    #[test]
    fn social_token_redirect_uri_matches_kiro_callback_path() {
        assert_eq!(
            social_token_redirect_uri("github"),
            "http://localhost:3128/oauth/callback?login_option=github"
        );
        assert_eq!(
            social_token_redirect_uri(""),
            "http://localhost:3128/oauth/callback"
        );
    }
}
