//! Native Rust implementation of the CPA Kiro provider plugin.
//!
//! The exported functions implement CPA's version 1 C ABI. JSON method payloads
//! remain the compatibility boundary with the host process.

#![deny(missing_docs)]

mod abi;
mod config;
mod dispatch;
#[path = "kiro-credentials.rs"]
pub mod kiro_credentials;
#[path = "kiro-event-stream.rs"]
pub mod kiro_event_stream;
#[path = "kiro-executor.rs"]
pub mod kiro_executor;
#[path = "kiro-models.rs"]
pub mod kiro_models;
#[path = "kiro-request-transform.rs"]
pub mod kiro_request_transform;

pub use abi::{cliproxy_buffer, cliproxy_host_api, cliproxy_plugin_api};

/// Initializes the plugin API table for CPA v8.
///
/// # Safety
/// CPA must pass a valid writable plugin API pointer. The host pointer may be
/// null because the registration shell does not call host callbacks yet.
#[no_mangle]
pub unsafe extern "C" fn cliproxy_plugin_init(
    host: *const cliproxy_host_api,
    plugin: *mut cliproxy_plugin_api,
) -> i32 {
    unsafe { abi::initialize_plugin(host, plugin) }
}

/// Dispatches one CPA method and writes an owned JSON response buffer.
///
/// # Safety
/// Pointers and lengths must follow the CPA ABI contract. Invalid pointers are
/// converted to structured errors where they can be detected safely.
#[no_mangle]
pub unsafe extern "C" fn cliproxyPluginCall(
    method: *const std::ffi::c_char,
    request: *const u8,
    request_len: usize,
    response: *mut cliproxy_buffer,
) -> i32 {
    unsafe { abi::call_plugin_method(method, request, request_len, response) }
}

/// Releases a response buffer allocated by this plugin.
///
/// # Safety
/// `ptr` must be a pointer previously returned by this plugin and `len` must
/// be the corresponding allocation length.
#[no_mangle]
pub unsafe extern "C" fn cliproxyPluginFree(ptr: *mut std::ffi::c_void, len: usize) {
    unsafe { abi::free_plugin_buffer(ptr, len) }
}

/// Releases process-wide plugin state before CPA unloads the library.
#[no_mangle]
pub extern "C" fn cliproxyPluginShutdown() {
    abi::shutdown_plugin();
}
