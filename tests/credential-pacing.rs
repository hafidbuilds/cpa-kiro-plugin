//! Per-credential pacing, benching, blocked-account disabling, and token
//! refresh-and-retry through the C ABI with a fake CPA host.

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::slice;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use kiro_go::{cliproxyPluginCall, cliproxyPluginFree, cliproxy_buffer, cliproxy_plugin_init};
use kiro_go::{cliproxy_host_api, cliproxy_plugin_api};
use serde_json::{json, Value};

#[derive(Default)]
struct FakeKiro {
    /// Status for each upstream open, consumed in order; 200 when empty.
    statuses: Vec<i64>,
    /// Body served with a non-200 upstream status.
    error_body: Vec<u8>,
    /// Upstream opens seen so far.
    opens: usize,
    /// Authorization header of each upstream open.
    authorizations: Vec<String>,
    /// Body still to serve for the current upstream stream.
    pending_body: Option<Vec<u8>>,
    /// Token refresh calls seen.
    refreshes: usize,
    /// `host.auth.save` requests seen.
    saves: Vec<Value>,
}

static FAKE: LazyLock<Mutex<FakeKiro>> = LazyLock::new(|| Mutex::new(FakeKiro::default()));
static TEST_LOCK: Mutex<()> = Mutex::new(());

const BLOCKED_BODY: &[u8] =
    br#"{"__type":"AccessDeniedException","message":"User is not authorized to make this call"}"#;
const INVALID_TOKEN_BODY: &[u8] =
    br#"{"message":"The bearer token included in the request is invalid."}"#;

fn assistant_frame() -> Vec<u8> {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/eventstream.json"))
        .expect("eventstream fixture");
    let hex = fixture["frames"]
        .as_array()
        .expect("frames")
        .iter()
        .find(|frame| frame["name"] == "assistant_hello")
        .and_then(|frame| frame["hex"].as_str())
        .expect("assistant_hello frame");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
        .collect()
}

fn ok(result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok": true, "result": result})).expect("envelope")
}

fn handle(method: &str, request: &Value) -> Vec<u8> {
    let mut fake = FAKE.lock().expect("fake lock");
    match method {
        "host.http.do"
            if request["url"]
                .as_str()
                .unwrap_or("")
                .contains("refreshToken") =>
        {
            fake.refreshes += 1;
            let body = json!({
                "accessToken": "fresh-access",
                "refreshToken": "fresh-refresh",
                "expiresIn": 3600
            });
            ok(json!({
                "status_code": 200,
                "body": base64::engine::general_purpose::STANDARD.encode(body.to_string())
            }))
        }
        "host.auth.save" => {
            fake.saves.push(request.clone());
            ok(json!({"name": request["name"], "path": "/auth"}))
        }
        "host.http.do_stream" => {
            fake.opens += 1;
            let authorization = request
                .pointer("/headers/Authorization/0")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            fake.authorizations.push(authorization);
            let status = if fake.statuses.is_empty() {
                200
            } else {
                fake.statuses.remove(0)
            };
            fake.pending_body = Some(if status == 200 {
                assistant_frame()
            } else {
                fake.error_body.clone()
            });
            ok(json!({"stream_id": "upstream", "status_code": status}))
        }
        "host.http.stream_read" => match fake.pending_body.take() {
            Some(body) => ok(json!({
                "payload": base64::engine::general_purpose::STANDARD.encode(body)
            })),
            None => ok(json!({"done": true})),
        },
        _ => ok(json!({})),
    }
}

unsafe extern "C" fn fake_host_call(
    _ctx: *mut c_void,
    method: *const c_char,
    request: *const u8,
    request_len: usize,
    response: *mut cliproxy_buffer,
) -> i32 {
    // SAFETY: The plugin passes a NUL-terminated method name.
    let method = unsafe { CStr::from_ptr(method) }
        .to_string_lossy()
        .into_owned();
    let request: Value = if request.is_null() || request_len == 0 {
        Value::Null
    } else {
        // SAFETY: The plugin passes a readable request buffer.
        serde_json::from_slice(unsafe { slice::from_raw_parts(request, request_len) })
            .unwrap_or(Value::Null)
    };
    let mut raw = handle(&method, &request).into_boxed_slice();
    // SAFETY: `response` is writable for this call.
    unsafe {
        (*response).ptr = raw.as_mut_ptr();
        (*response).len = raw.len();
    }
    std::mem::forget(raw);
    0
}

unsafe extern "C" fn fake_host_free(ptr: *mut c_void, len: usize) {
    if !ptr.is_null() {
        // SAFETY: Allocated by `fake_host_call` as a boxed slice of `len` bytes.
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), len)) });
    }
}

fn call_plugin(method: &str, request: &Value) -> Value {
    let method = CString::new(method).expect("method");
    let request = serde_json::to_vec(request).expect("request");
    let mut response = cliproxy_buffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: Valid pointers for the duration of the call.
    unsafe {
        cliproxyPluginCall(
            method.as_ptr(),
            request.as_ptr(),
            request.len(),
            &mut response,
        )
    };
    // SAFETY: The plugin returned an owned buffer.
    let raw = unsafe { slice::from_raw_parts(response.ptr, response.len) }.to_vec();
    // SAFETY: Released exactly once.
    unsafe { cliproxyPluginFree(response.ptr.cast(), response.len) };
    serde_json::from_slice(&raw).expect("plugin response JSON")
}

fn setup(yaml: &str, statuses: Vec<i64>, error_body: &[u8]) {
    *FAKE.lock().expect("fake lock") = FakeKiro {
        statuses,
        error_body: error_body.to_vec(),
        ..FakeKiro::default()
    };
    let host = cliproxy_host_api {
        abi_version: 1,
        host_ctx: ptr::null_mut(),
        call: Some(fake_host_call),
        free_buffer: Some(fake_host_free),
    };
    let mut plugin = cliproxy_plugin_api {
        abi_version: 0,
        call: None,
        free_buffer: None,
        shutdown: None,
    };
    // SAFETY: Both tables are valid for the call.
    assert_eq!(unsafe { cliproxy_plugin_init(&host, &mut plugin) }, 0);
    let config = json!({"config_yaml": base64::engine::general_purpose::STANDARD.encode(yaml)});
    let registered = call_plugin("plugin.reconfigure", &config);
    assert_eq!(registered["ok"], true, "{registered}");
}

fn api_key_storage() -> Value {
    std::env::set_var("KIRO_PACING_TEST_KEY", "test-api-key");
    json!({"type": "kiro", "api_key_env": "KIRO_PACING_TEST_KEY", "region": "us-east-1"})
}

fn desktop_storage() -> Value {
    json!({
        "type": "kiro",
        "auth_method": "desktop",
        "region": "us-east-1",
        "profile_arn": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
        "access_token": "stale-access",
        "refresh_token": "old-refresh",
        "expired": "2999-01-01T00:00:00Z",
        "custom_field": "kept"
    })
}

fn execute(method: &str, auth_id: &str, storage: &Value) -> Value {
    let payload = json!({
        "model": "claude-haiku-5.5",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hello"}]
    });
    call_plugin(
        method,
        &json!({
            "AuthID": auth_id,
            "AuthAttributes": {"path": format!("/auth/{auth_id}")},
            "Model": "claude-haiku-5.5",
            "Payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
            "StorageJSON": base64::engine::general_purpose::STANDARD.encode(storage.to_string()),
            "stream_id": "plugin-stream"
        }),
    )
}

#[test]
fn blocked_account_is_disabled_and_benched_without_another_upstream_call() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    setup(
        "min_token_interval: 0s\nmax_token_interval: 0s\nsuspend_cooldown: 1h\n",
        vec![403],
        BLOCKED_BODY,
    );

    let first = execute("executor.execute", "kiro-blocked.json", &desktop_storage());
    assert_eq!(first["ok"], false, "{first}");
    assert_eq!(first["error"]["http_status"], 403);
    {
        let fake = FAKE.lock().expect("fake lock");
        assert_eq!(fake.opens, 1);
        assert_eq!(fake.saves.len(), 1, "blocked account was not written back");
        let saved = &fake.saves[0];
        assert_eq!(saved["name"], "kiro-blocked.json");
        assert_eq!(saved["json"]["disabled"], true);
        assert_eq!(saved["json"]["custom_field"], "kept");
        assert!(saved["json"]["note"]
            .as_str()
            .unwrap_or("")
            .contains("User is not authorized"));
        assert!(!saved["json"]["blocked_at"]
            .as_str()
            .unwrap_or("")
            .is_empty());
    }

    let second = execute("executor.execute", "kiro-blocked.json", &desktop_storage());
    assert_eq!(second["error"]["code"], "account_suspended", "{second}");
    assert_eq!(second["error"]["http_status"], 403);
    assert!(
        second["error"]["retry_after_seconds"]
            .as_i64()
            .unwrap_or_default()
            > 3500
    );
    assert_eq!(
        FAKE.lock().expect("fake lock").opens,
        1,
        "a benched credential must not reach Kiro"
    );

    // Another account is unaffected.
    let other = execute("executor.execute", "kiro-other.json", &api_key_storage());
    assert_eq!(other["ok"], true, "{other}");
}

#[test]
fn rejected_token_is_refreshed_saved_and_retried_once() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (method, auth_id) in [
        ("executor.execute", "kiro-refresh-a.json"),
        ("executor.execute_stream", "kiro-refresh-b.json"),
    ] {
        setup(
            "min_token_interval: 0s\nmax_token_interval: 0s\n",
            vec![403],
            INVALID_TOKEN_BODY,
        );
        let response = execute(method, auth_id, &desktop_storage());
        assert_eq!(response["ok"], true, "{method}: {response}");

        let fake = FAKE.lock().expect("fake lock");
        assert_eq!(fake.refreshes, 1, "{method}");
        assert_eq!(
            fake.authorizations,
            ["Bearer stale-access", "Bearer fresh-access"],
            "{method}"
        );
        assert_eq!(fake.saves.len(), 1, "{method}: refreshed token not saved");
        let saved = &fake.saves[0];
        assert_eq!(saved["name"], auth_id);
        assert_eq!(saved["json"]["access_token"], "fresh-access");
        assert_eq!(saved["json"]["refresh_token"], "fresh-refresh");
        assert_eq!(saved["json"]["custom_field"], "kept");
    }

    // A later request still holding the pre-refresh snapshot uses the new
    // tokens instead of the retired ones, without refreshing again.
    setup(
        "min_token_interval: 0s\nmax_token_interval: 0s\n",
        Vec::new(),
        b"",
    );
    let response = execute(
        "executor.execute",
        "kiro-refresh-a.json",
        &desktop_storage(),
    );
    assert_eq!(response["ok"], true, "{response}");
    let fake = FAKE.lock().expect("fake lock");
    assert_eq!(fake.refreshes, 0);
    assert_eq!(fake.authorizations, ["Bearer fresh-access"]);
}

#[test]
fn back_to_back_requests_on_one_account_are_spaced() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    setup(
        "min_token_interval: 300ms\nmax_token_interval: 400ms\n",
        Vec::new(),
        b"",
    );
    let started = Instant::now();
    assert_eq!(
        execute("executor.execute", "kiro-paced.json", &api_key_storage())["ok"],
        true
    );
    assert_eq!(
        execute("executor.execute", "kiro-paced.json", &api_key_storage())["ok"],
        true
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(200),
        "second request was not paced: {elapsed:?}"
    );
    // A different account is not held back by the first one's slot.
    let started = Instant::now();
    assert_eq!(
        execute("executor.execute", "kiro-unpaced.json", &api_key_storage())["ok"],
        true
    );
    assert!(started.elapsed() < Duration::from_millis(200));
}
