use std::ffi::{c_char, c_void, CString};
use std::ptr;
use std::sync::Mutex;

use serde_json::Value;

use kiro_go::{
    cliproxyPluginCall, cliproxyPluginFree, cliproxy_buffer, cliproxy_plugin_api,
    cliproxy_plugin_init,
};

static ABI_LIFECYCLE_LOCK: Mutex<()> = Mutex::new(());

fn read_response(buffer: &cliproxy_buffer) -> String {
    assert!(!buffer.ptr.is_null());
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
    String::from_utf8(bytes.to_vec()).expect("plugin response must be UTF-8")
}

#[test]
fn plugin_initialization_installs_versioned_callbacks() {
    let _guard = ABI_LIFECYCLE_LOCK.lock().expect("ABI lifecycle lock");
    let mut plugin = cliproxy_plugin_api {
        abi_version: 0,
        call: None,
        free_buffer: None,
        shutdown: None,
    };
    let result = unsafe { cliproxy_plugin_init(ptr::null(), &mut plugin) };
    assert_eq!(result, 0);
    assert_eq!(plugin.abi_version, 1);
    assert!(plugin.call.is_some());
    assert!(plugin.free_buffer.is_some());
    assert!(plugin.shutdown.is_some());
    unsafe { (plugin.shutdown.expect("shutdown callback"))() };
}

#[test]
fn plugin_can_repeat_initialization_call_and_shutdown_cycles() {
    let _guard = ABI_LIFECYCLE_LOCK.lock().expect("ABI lifecycle lock");
    for _ in 0..3 {
        let mut plugin = cliproxy_plugin_api {
            abi_version: 0,
            call: None,
            free_buffer: None,
            shutdown: None,
        };
        assert_eq!(unsafe { cliproxy_plugin_init(ptr::null(), &mut plugin) }, 0);
        let method = CString::new("auth.identifier").expect("method has no NUL");
        let mut response = cliproxy_buffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            unsafe { cliproxyPluginCall(method.as_ptr(), ptr::null(), 0, &mut response) },
            0
        );
        let body: Value =
            serde_json::from_str(&read_response(&response)).expect("identifier response JSON");
        assert_eq!(body["ok"], true);
        assert_eq!(body["result"]["identifier"], "kiro");
        unsafe { cliproxyPluginFree(response.ptr.cast::<c_void>(), response.len) };
        unsafe { (plugin.shutdown.expect("shutdown callback"))() };
    }
}

#[test]
fn plugin_registration_returns_kiro_capabilities() {
    let method = CString::new("plugin.register").expect("method has no NUL");
    let mut response = cliproxy_buffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let result = unsafe { cliproxyPluginCall(method.as_ptr(), ptr::null(), 0, &mut response) };
    let body = read_response(&response);
    assert_eq!(result, 0);
    assert!(body.contains("\"model_registrar\":true"));
    assert!(body.contains("\"executor_input_formats\":[\"claude\"]"));
    unsafe { cliproxyPluginFree(response.ptr.cast::<c_void>(), response.len) };
}

#[test]
fn null_method_returns_structured_invalid_method_error() {
    let mut response = cliproxy_buffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let result =
        unsafe { cliproxyPluginCall(ptr::null::<c_char>(), ptr::null(), 0, &mut response) };
    let body = read_response(&response);
    assert_eq!(result, 1);
    assert!(body.contains("\"code\":\"invalid_method\""));
    unsafe { cliproxyPluginFree(response.ptr.cast::<c_void>(), response.len) };
}

#[test]
fn unknown_method_returns_searchable_error_code() {
    let method = CString::new("kiro.unknown").expect("method has no NUL");
    let mut response = cliproxy_buffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let result = unsafe { cliproxyPluginCall(method.as_ptr(), ptr::null(), 0, &mut response) };
    let body = read_response(&response);
    assert_eq!(result, 1);
    assert!(body.contains("\"code\":\"unknown_method\""));
    unsafe { cliproxyPluginFree(response.ptr.cast::<c_void>(), response.len) };
}
