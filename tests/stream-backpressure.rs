//! Regression test for streaming against a host that mirrors CPA's stream bridge.
//!
//! CPA (`internal/pluginhost/stream_bridge.go`) buffers at most 16 emitted
//! chunks and only starts draining them after `executor.execute_stream`
//! returns. A plugin that pumps the whole upstream body inside that call
//! blocks on the 17th `host.stream.emit` forever. This fake host reproduces
//! that contract, but fails an emit after a timeout instead of hanging the test.

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::slice;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use kiro_go::{cliproxyPluginCall, cliproxyPluginFree, cliproxy_buffer, cliproxy_plugin_init};
use kiro_go::{cliproxy_host_api, cliproxy_plugin_api};
use serde_json::{json, Value};

/// Matches `streamBridgeBufferSize` in CPA.
const CPA_STREAM_BUFFER: usize = 16;
/// Upstream assistant events served by the fake Kiro stream.
const UPSTREAM_EVENTS: usize = 40;
/// How long a blocked emit waits before the fake host reports failure.
const EMIT_BLOCK_TIMEOUT: Duration = Duration::from_secs(3);

enum Output {
    Chunk(Vec<u8>),
    Close(Option<String>),
}

struct FakeHost {
    output: SyncSender<Output>,
    reads_served: usize,
    upstream_closed: bool,
}

static FAKE_HOST: LazyLock<Mutex<Option<FakeHost>>> = LazyLock::new(|| Mutex::new(None));

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
    serde_json::to_vec(&json!({"ok": true, "result": result})).expect("encode envelope")
}

fn fail(message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok": false, "error": {"code": "host_error", "message": message}}))
        .expect("encode envelope")
}

fn handle_host_method(method: &str, request: &Value) -> Vec<u8> {
    match method {
        "host.http.do_stream" => ok(json!({"stream_id": "upstream-1", "status_code": 200})),
        "host.http.stream_read" => {
            let mut guard = FAKE_HOST.lock().expect("fake host lock");
            let host = guard.as_mut().expect("fake host installed");
            if host.reads_served >= UPSTREAM_EVENTS {
                return ok(json!({"done": true}));
            }
            host.reads_served += 1;
            let payload = base64::engine::general_purpose::STANDARD.encode(assistant_frame());
            ok(json!({"payload": payload}))
        }
        "host.http.stream_close" => {
            if let Some(host) = FAKE_HOST.lock().expect("fake host lock").as_mut() {
                host.upstream_closed = true;
            }
            ok(json!({}))
        }
        "host.stream.emit" => {
            let payload = base64::engine::general_purpose::STANDARD
                .decode(request["payload"].as_str().unwrap_or_default())
                .expect("emit payload is Base64");
            let sender = FAKE_HOST
                .lock()
                .expect("fake host lock")
                .as_ref()
                .expect("fake host installed")
                .output
                .clone();
            let deadline = Instant::now() + EMIT_BLOCK_TIMEOUT;
            let mut item = Output::Chunk(payload);
            loop {
                match sender.try_send(item) {
                    Ok(()) => return ok(json!({})),
                    Err(TrySendError::Full(returned)) if Instant::now() < deadline => {
                        item = returned;
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return fail("stream bridge full: emit blocked"),
                }
            }
        }
        "host.stream.close" => {
            let error = request["error"].as_str().map(str::to_owned);
            let sender = FAKE_HOST
                .lock()
                .expect("fake host lock")
                .as_ref()
                .expect("fake host installed")
                .output
                .clone();
            let _ = sender.send_timeout_compat(Output::Close(error));
            ok(json!({}))
        }
        "host.log" => ok(json!({})),
        other => fail(&format!("unexpected host method {other}")),
    }
}

trait SendTimeoutCompat {
    fn send_timeout_compat(&self, item: Output) -> Result<(), ()>;
}

impl SendTimeoutCompat for SyncSender<Output> {
    fn send_timeout_compat(&self, mut item: Output) -> Result<(), ()> {
        let deadline = Instant::now() + EMIT_BLOCK_TIMEOUT;
        loop {
            match self.try_send(item) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(returned)) if Instant::now() < deadline => {
                    item = returned;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(()),
            }
        }
    }
}

unsafe extern "C" fn fake_host_call(
    _ctx: *mut c_void,
    method: *const c_char,
    request: *const u8,
    request_len: usize,
    response: *mut cliproxy_buffer,
) -> i32 {
    // SAFETY: The plugin passes a NUL-terminated method and a readable request.
    let method = unsafe { CStr::from_ptr(method) }
        .to_str()
        .expect("method is UTF-8");
    let request: Value = if request.is_null() || request_len == 0 {
        Value::Null
    } else {
        // SAFETY: See above.
        serde_json::from_slice(unsafe { slice::from_raw_parts(request, request_len) })
            .expect("host request JSON")
    };
    let mut raw = handle_host_method(method, &request).into_boxed_slice();
    // SAFETY: `response` is writable plugin storage for this call.
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

fn call_plugin(method: &str, request: &[u8]) -> (i32, Value) {
    let method = CString::new(method).expect("method");
    let mut response = cliproxy_buffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: Valid method, request, and response pointers for this call.
    let status = unsafe {
        cliproxyPluginCall(
            method.as_ptr(),
            request.as_ptr(),
            request.len(),
            &mut response,
        )
    };
    // SAFETY: The plugin returned an owned buffer.
    let raw = unsafe { slice::from_raw_parts(response.ptr, response.len) }.to_vec();
    // SAFETY: Releases the plugin-owned buffer exactly once.
    unsafe { cliproxyPluginFree(response.ptr.cast(), response.len) };
    (
        status,
        serde_json::from_slice(&raw).expect("plugin response JSON"),
    )
}

fn install_fake_host() -> Receiver<Output> {
    let (sender, receiver) = sync_channel(CPA_STREAM_BUFFER);
    *FAKE_HOST.lock().expect("fake host lock") = Some(FakeHost {
        output: sender,
        reads_served: 0,
        upstream_closed: false,
    });
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
    // SAFETY: Both tables are valid for the duration of the call.
    assert_eq!(unsafe { cliproxy_plugin_init(&host, &mut plugin) }, 0);
    receiver
}

#[test]
fn execute_stream_returns_before_draining_and_delivers_every_chunk() {
    std::env::set_var("KIRO_STREAM_TEST_KEY", "test-api-key");
    let output = install_fake_host();
    let storage = json!({
        "type": "kiro",
        "api_key_env": "KIRO_STREAM_TEST_KEY",
        "region": "us-east-1"
    });
    let payload = json!({
        "model": "claude-sonnet-4.5",
        "max_tokens": 32,
        "stream": true,
        "messages": [{"role": "user", "content": "hello"}]
    });
    let request = json!({
        "Model": "claude-sonnet-4.5",
        "Stream": true,
        "Payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
        "StorageJSON": base64::engine::general_purpose::STANDARD.encode(storage.to_string()),
        "stream_id": "plugin-stream-1"
    });

    let started = Instant::now();
    let (status, response) = call_plugin(
        "executor.execute_stream",
        &serde_json::to_vec(&request).expect("request JSON"),
    );
    let call_duration = started.elapsed();
    assert_eq!(status, 0, "execute_stream failed: {response}");
    assert_eq!(response["ok"], true, "execute_stream failed: {response}");
    assert!(
        call_duration < EMIT_BLOCK_TIMEOUT,
        "execute_stream blocked for {call_duration:?} before CPA could drain the stream"
    );

    // CPA starts draining only now, after the call returned.
    let mut chunks = 0;
    let mut sse = String::new();
    let close_error = loop {
        match output.recv_timeout(Duration::from_secs(10)) {
            Ok(Output::Chunk(bytes)) => {
                chunks += 1;
                sse.push_str(&String::from_utf8_lossy(&bytes));
            }
            Ok(Output::Close(error)) => break error,
            Err(RecvTimeoutError::Timeout) => panic!("stream never closed"),
            Err(RecvTimeoutError::Disconnected) => panic!("fake host dropped"),
        }
    };

    assert_eq!(close_error.filter(|error| !error.is_empty()), None);
    assert!(
        chunks > CPA_STREAM_BUFFER,
        "expected more than {CPA_STREAM_BUFFER} chunks to exercise backpressure, got {chunks}"
    );
    assert!(sse.contains("event: message_start"), "{sse}");
    assert!(sse.contains("event: message_stop"), "{sse}");
    assert!(
        FAKE_HOST
            .lock()
            .expect("fake host lock")
            .as_ref()
            .expect("fake host installed")
            .upstream_closed,
        "upstream HTTP stream was not closed"
    );
}
