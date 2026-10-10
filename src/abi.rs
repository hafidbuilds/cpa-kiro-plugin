//! CPA C ABI layouts, pointer validation, and plugin-owned buffer handling.

use std::ffi::{c_char, c_void, CStr};
use std::ptr;
use std::slice;
use std::sync::{LazyLock, Mutex};

use crate::dispatch;

/// CPA native ABI version implemented by this library.
pub const CPA_ABI_VERSION: u32 = 1;

/// Owned byte buffer exchanged across the CPA ABI.
#[repr(C)]
pub struct cliproxy_buffer {
    /// Pointer to the first byte, or null for an empty buffer.
    pub ptr: *mut u8,
    /// Number of bytes owned by `ptr`.
    pub len: usize,
}

/// Host callback function type used by CPA v8.
pub type HostCall =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const u8, usize, *mut cliproxy_buffer) -> i32;
/// Host buffer release function type used by CPA v8.
pub type HostFree = unsafe extern "C" fn(*mut c_void, usize);
/// Plugin method callback function type installed into CPA.
pub type PluginCall =
    unsafe extern "C" fn(*const c_char, *const u8, usize, *mut cliproxy_buffer) -> i32;
/// Plugin buffer release function type installed into CPA.
pub type PluginFree = unsafe extern "C" fn(*mut c_void, usize);
/// Plugin shutdown callback type installed into CPA.
pub type PluginShutdown = unsafe extern "C" fn();

/// Host callback table supplied by CPA v8.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct cliproxy_host_api {
    /// ABI version advertised by CPA.
    pub abi_version: u32,
    /// Opaque host callback context.
    pub host_ctx: *mut c_void,
    /// Host method invocation callback.
    pub call: Option<HostCall>,
    /// Host-owned buffer release callback.
    pub free_buffer: Option<HostFree>,
}

/// Plugin callback table populated during initialization.
#[repr(C)]
pub struct cliproxy_plugin_api {
    /// ABI version selected by the plugin.
    pub abi_version: u32,
    /// Plugin method invocation callback.
    pub call: Option<PluginCall>,
    /// Plugin-owned buffer release callback.
    pub free_buffer: Option<PluginFree>,
    /// Plugin shutdown callback.
    pub shutdown: Option<PluginShutdown>,
}

static HOST_API: LazyLock<Mutex<Option<HostSnapshot>>> = LazyLock::new(|| Mutex::new(None));

#[derive(Clone, Copy)]
struct HostSnapshot {
    host_ctx: *mut c_void,
    call: Option<HostCall>,
    free_buffer: Option<HostFree>,
}

// CPA owns the context through plugin shutdown; callback invocations copy it
// under lock and release the lock before crossing the FFI boundary.
unsafe impl Send for HostSnapshot {}

/// Initializes the plugin callback table and records the host ABI version.
///
/// # Safety
/// `plugin`, when non-null, must point to writable CPA storage. `host` must
/// point to a valid host table when provided.
pub unsafe fn initialize_plugin(
    host: *const cliproxy_host_api,
    plugin: *mut cliproxy_plugin_api,
) -> i32 {
    if plugin.is_null() {
        return 1;
    }
    if !host.is_null() {
        // SAFETY: The caller supplied a non-null ABI table pointer.
        let host_value = unsafe { *host };
        if let Ok(mut stored_host) = HOST_API.lock() {
            *stored_host = Some(HostSnapshot {
                host_ctx: host_value.host_ctx,
                call: host_value.call,
                free_buffer: host_value.free_buffer,
            });
        }
    }
    // SAFETY: `plugin` was checked for null and belongs to CPA.
    unsafe {
        (*plugin).abi_version = CPA_ABI_VERSION;
        (*plugin).call = Some(crate::cliproxyPluginCall);
        (*plugin).free_buffer = Some(crate::cliproxyPluginFree);
        (*plugin).shutdown = Some(crate::cliproxyPluginShutdown);
    }
    0
}

/// Dispatches a method after validating the borrowed C ABI inputs.
///
/// # Safety
/// The pointers must be valid for the supplied lengths according to CPA's ABI.
pub unsafe fn call_plugin_method(
    method: *const c_char,
    request: *const u8,
    request_len: usize,
    response: *mut cliproxy_buffer,
) -> i32 {
    initialize_response_buffer(response);
    if response.is_null() {
        return 1;
    }
    let Some(method) = (if method.is_null() {
        None
    } else {
        // SAFETY: CPA passes a NUL-terminated method string.
        unsafe { CStr::from_ptr(method).to_str().ok() }
    }) else {
        write_error(response, "invalid_method", "method is required");
        return 1;
    };
    let request = if request.is_null() || request_len == 0 {
        &[]
    } else {
        // SAFETY: CPA owns a readable request buffer for this call duration.
        unsafe { slice::from_raw_parts(request, request_len) }
    };
    match dispatch::dispatch_method(method, request) {
        Ok(raw) => {
            write_plugin_buffer(response, &raw);
            0
        }
        Err(error) => {
            write_error(response, error.code, &error.message);
            1
        }
    }
}

fn initialize_response_buffer(response: *mut cliproxy_buffer) {
    if !response.is_null() {
        // SAFETY: A non-null response pointer is writable CPA storage.
        unsafe {
            (*response).ptr = ptr::null_mut();
            (*response).len = 0;
        }
    }
}

fn write_error(response: *mut cliproxy_buffer, code: &str, message: &str) {
    let http_status = match code {
        "invalid_auth" | "refresh_failed" => 401,
        "model_not_found" => 404,
        "rate_limit" => 429,
        "executor_error" => 502,
        _ => 0,
    };
    let raw = serde_json::json!({
        "ok": false,
        "error": {"code": code, "message": message, "http_status": http_status}
    })
    .to_string();
    write_plugin_buffer(response, raw.as_bytes());
}

fn write_plugin_buffer(response: *mut cliproxy_buffer, raw: &[u8]) {
    if response.is_null() || raw.is_empty() {
        return;
    }
    let mut owned = raw.to_vec().into_boxed_slice();
    let ptr = owned.as_mut_ptr();
    let len = owned.len();
    std::mem::forget(owned);
    // SAFETY: `response` is writable storage and `ptr` is retained allocation.
    unsafe {
        (*response).ptr = ptr;
        (*response).len = len;
    }
}

/// Releases a buffer allocated by `write_plugin_buffer`.
///
/// # Safety
/// The pointer and length must describe one allocation from this plugin.
pub unsafe fn free_plugin_buffer(ptr: *mut c_void, len: usize) {
    if !ptr.is_null() {
        // SAFETY: The ABI contract requires a matching pointer and length.
        unsafe {
            let allocation = ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), len);
            drop(Box::from_raw(allocation));
        }
    }
}

/// Invokes one CPA host callback and returns its unwrapped JSON result.
///
/// The callback response is copied before the host-owned buffer is released.
pub(crate) fn invoke_host_json(method: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let host = HOST_API
        .lock()
        .map_err(|_| "Kiro host callback table lock poisoned".to_string())?
        .ok_or_else(|| "Kiro host callback table is not initialized".to_string())?;
    let call = host
        .call
        .ok_or_else(|| "Kiro host callback function is unavailable".to_string())?;
    let method = std::ffi::CString::new(method)
        .map_err(|_| format!("host callback method contains NUL: {method}"))?;
    let mut response = cliproxy_buffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let request_ptr = if payload.is_empty() {
        ptr::null()
    } else {
        payload.as_ptr()
    };
    // SAFETY: All pointers remain valid for the synchronous host call.
    let code = unsafe {
        call(
            host.host_ctx,
            method.as_ptr(),
            request_ptr,
            payload.len(),
            &mut response,
        )
    };
    let response_bytes = if response.ptr.is_null() || response.len == 0 {
        Vec::new()
    } else {
        // SAFETY: The host returned a readable response buffer for this call.
        unsafe { slice::from_raw_parts(response.ptr, response.len).to_vec() }
    };
    if let Some(free_buffer) = host.free_buffer {
        if !response.ptr.is_null() {
            // SAFETY: CPA's host free callback receives the returned pointer and length.
            unsafe { free_buffer(response.ptr.cast(), response.len) };
        }
    }
    if code != 0 {
        return Err(format!("host callback {method:?} returned code {code}"));
    }
    let envelope: serde_json::Value = serde_json::from_slice(&response_bytes)
        .map_err(|error| format!("decode host callback {method:?}: {error}"))?;
    if envelope.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(envelope
            .pointer("/error/message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("host callback failed")
            .to_string());
    }
    serde_json::to_vec(envelope.get("result").unwrap_or(&serde_json::Value::Null))
        .map_err(|error| format!("encode host callback result {method:?}: {error}"))
}

/// Drops process-local callback state after CPA shutdown.
pub fn shutdown_plugin() {
    crate::dispatch::clear_pending_kiro_logins();
    if let Ok(mut host) = HOST_API.lock() {
        let _ = host.take();
    }
}
