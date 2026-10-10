use std::ffi::CString;
use std::ptr;

use base64::Engine;
use kiro_go::{cliproxyPluginCall, cliproxyPluginFree, cliproxy_buffer};
use serde_json::{json, Value};
use std::sync::Mutex;

static COMPATIBILITY_TEST_LOCK: Mutex<()> = Mutex::new(());

fn call_plugin(method: &str, request: &[u8]) -> (i32, Value) {
    let method = CString::new(method).expect("method has no NUL");
    let mut response = cliproxy_buffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let request_ptr = if request.is_empty() {
        ptr::null()
    } else {
        request.as_ptr()
    };
    let status =
        unsafe { cliproxyPluginCall(method.as_ptr(), request_ptr, request.len(), &mut response) };
    let body = if response.ptr.is_null() {
        String::new()
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(response.ptr, response.len) };
        String::from_utf8(bytes.to_vec()).expect("plugin response must be UTF-8")
    };
    if !response.ptr.is_null() {
        unsafe { cliproxyPluginFree(response.ptr.cast(), response.len) };
    }
    (
        status,
        serde_json::from_str(&body).expect("plugin response JSON"),
    )
}

fn restore_default_config() {
    let _ = call_plugin("plugin.reconfigure", b"");
}

fn reconfigure_yaml(yaml: &str) -> Value {
    let request = json!({
        "config_yaml": base64::engine::general_purpose::STANDARD.encode(yaml)
    });
    call_plugin(
        "plugin.reconfigure",
        &serde_json::to_vec(&request).expect("reconfigure request"),
    )
    .1
}

fn model_ids(response: &Value) -> Vec<&str> {
    response
        .pointer("/result/Models")
        .and_then(Value::as_array)
        .expect("models")
        .iter()
        .map(|model| model["ID"].as_str().expect("model ID"))
        .collect()
}

fn fixture_json(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("fixture JSON")
}

#[test]
fn request_transform_matches_go_fixture_payload_except_generated_continuation_id() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    let fixture = fixture_json("executor.json");
    let payload = base64::engine::general_purpose::STANDARD
        .decode(
            fixture["execute"]["request"]["Payload"]
                .as_str()
                .expect("Payload"),
        )
        .expect("request payload base64");
    let (translated, _) = kiro_go::kiro_request_transform::translate_claude_request_to_kiro(
        &payload,
        "claude-sonnet-4.5",
    )
    .expect("request translation");
    let mut actual = serde_json::to_value(translated).expect("translated payload JSON");
    let mut expected = fixture["execute"]["upstream"]["body"].clone();
    actual["conversationState"]
        .as_object_mut()
        .expect("conversation state object")
        .remove("agentContinuationId");
    expected["conversationState"]
        .as_object_mut()
        .expect("conversation state object")
        .remove("agentContinuationId");
    assert_eq!(
        actual, expected,
        "generated wire payload must match the frozen Go contract"
    );
}

#[test]
fn plugin_register_declares_schema_capabilities_and_claude_formats() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    restore_default_config();
    let expected = fixture_json("plugin-register.json");
    let (status, response) = call_plugin("plugin.register", b"");
    assert_eq!(status, 0);
    assert_eq!(response["ok"], true);
    assert_eq!(
        response["result"]["schema_version"],
        expected["response"]["result"]["schema_version"]
    );
    assert_eq!(
        response["result"]["metadata"]["Name"],
        expected["response"]["result"]["metadata"]["Name"]
    );
    assert_eq!(
        response["result"]["capabilities"],
        expected["response"]["result"]["capabilities"]
    );
    let fields: Vec<&str> = response["result"]["metadata"]["ConfigFields"]
        .as_array()
        .expect("config fields")
        .iter()
        .map(|field| field["Name"].as_str().expect("field name"))
        .collect();
    assert_eq!(
        fields,
        ["models", "kiro_version", "node_version", "system_version"]
    );
}

#[test]
fn model_static_lists_default_ids_after_empty_registration() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    restore_default_config();
    let expected = fixture_json("models.json");
    let (status, response) = call_plugin("model.static", b"");
    assert_eq!(status, 0);
    assert_eq!(
        model_ids(&response),
        expected["configured_model_ids"]
            .as_array()
            .expect("configured ids")
            .iter()
            .map(|id| id.as_str().expect("id"))
            .collect::<Vec<_>>()
    );
    assert_eq!(response["result"]["Provider"], "kiro");
    assert_eq!(response["result"]["Models"][0]["Type"], "claude");
    assert_eq!(response["result"]["Models"][0]["OwnedBy"], "kiro");
}

#[test]
fn model_static_keeps_configured_allowlist() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    restore_default_config();
    reconfigure_yaml("models: [\"claude-haiku-4.5\"]\n");
    let (status, response) = call_plugin("model.static", b"");
    restore_default_config();
    assert_eq!(status, 0);
    assert_eq!(model_ids(&response), ["claude-haiku-4.5"]);
}

#[test]
fn model_static_expands_wildcard_to_default_models() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    restore_default_config();
    reconfigure_yaml(
        "enabled: true\nmodels: [\"*\"]\nkiro_version: \"0.11.107\"\nnode_version: \"22.22.0\"\nsystem_version: \"linux#6.6.87\"\n",
    );
    let (status, response) = call_plugin("model.static", b"");
    restore_default_config();
    assert_eq!(status, 0);
    assert_eq!(
        model_ids(&response),
        ["claude-sonnet-4.5", "claude-haiku-4.5"]
    );
}

#[test]
fn auth_parse_returns_api_key_envelope_without_environment_secret() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    let fixture = fixture_json("auth-parse-refresh.json");
    let expected = &fixture["parse"]["api_key_env"]["response"];
    std::env::set_var("KIRO_TEST_KEY", "REDACTED_SECRET_MUST_NOT_LEAK");
    let request = serde_json::to_vec(&fixture["parse"]["api_key_env"]["request"])
        .expect("auth parse request");
    let (status, response) = call_plugin("auth.parse", &request);
    assert_eq!(status, 0);
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["Handled"], true);
    let auth = &response["result"]["Auth"];
    assert_eq!(auth["Provider"], expected["result"]["Auth"]["Provider"]);
    assert_eq!(auth["ID"], expected["result"]["Auth"]["ID"]);
    assert_eq!(auth["FileName"], expected["result"]["Auth"]["FileName"]);
    assert_eq!(auth["Label"], expected["result"]["Auth"]["Label"]);
    assert_eq!(auth["Metadata"]["auth_method"], "apikey");
    assert_eq!(auth["Metadata"]["auth_kind"], "api_key");
    assert_eq!(auth["Metadata"]["key_source"], "env:KIRO_TEST_KEY");
    assert_eq!(auth["Metadata"]["key_present"], true);
    assert_eq!(auth["Attributes"]["auth_kind"], "api_key");
    let storage = base64::engine::general_purpose::STANDARD
        .decode(auth["StorageJSON"].as_str().expect("StorageJSON"))
        .expect("StorageJSON is Base64");
    let storage: Value = serde_json::from_slice(&storage).expect("storage JSON");
    assert_eq!(storage["type"], "kiro");
    assert_eq!(storage["auth_method"], "apikey");
    assert_eq!(storage["api_key_env"], "KIRO_TEST_KEY");
    assert_eq!(storage.get("api_key"), None);
    assert!(!serde_json::to_string(&storage)
        .expect("storage text")
        .contains("REDACTED_SECRET_MUST_NOT_LEAK"));
}

#[test]
fn auth_parse_returns_idc_oauth_envelope_shape() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    let fixture = fixture_json("auth-parse-refresh.json");
    let request =
        serde_json::to_vec(&fixture["parse"]["idc_oauth"]["request"]).expect("idc parse request");
    let (status, response) = call_plugin("auth.parse", &request);
    assert_eq!(status, 0);
    assert_eq!(response["ok"], true);
    let auth = &response["result"]["Auth"];
    assert_eq!(auth["Provider"], "kiro");
    assert_eq!(auth["ID"], "kiro-test.json");
    assert_eq!(auth["Label"], "kiro-test");
    assert_eq!(auth["Metadata"]["auth_kind"], "oauth");
    assert_eq!(auth["Metadata"]["auth_method"], "idc");
    assert_eq!(auth["Metadata"]["access_token"], "REDACTED_ACCESS_TOKEN");
    assert_eq!(auth["Metadata"]["refresh_token"], "REDACTED_REFRESH_TOKEN");
    assert_eq!(
        auth["Metadata"]["profile_arn"],
        "arn:aws:codewhisperer:us-east-1:111111111111:profile/IDCTEST"
    );
    let interval = auth["Metadata"]["refresh_interval_seconds"]
        .as_u64()
        .expect("refresh interval");
    assert!(interval >= 60);
    let storage = base64::engine::general_purpose::STANDARD
        .decode(auth["StorageJSON"].as_str().expect("StorageJSON"))
        .expect("StorageJSON is Base64");
    let storage: Value = serde_json::from_slice(&storage).expect("storage JSON");
    assert_eq!(storage["auth_method"], "idc");
    assert_eq!(storage["client_secret"], "REDACTED_CLIENT_SECRET");
}

#[test]
fn auth_parse_ignores_non_kiro_records() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    let fixture = fixture_json("auth-parse-refresh.json");
    let request =
        serde_json::to_vec(&fixture["parse"]["unhandled"]["request"]).expect("unhandled request");
    let (status, response) = call_plugin("auth.parse", &request);
    assert_eq!(status, 0);
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["Handled"], false);
    assert_eq!(response["result"].get("Auth"), None);
}

#[test]
fn auth_parse_rejects_invalid_region_with_invalid_auth() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    let fixture = fixture_json("auth-parse-refresh.json");
    let raw = serde_json::to_vec(&fixture["parse"]["invalid_region"]["request_storage_object"])
        .expect("invalid region storage");
    let request = json!({
        "FileName": "evil.json",
        "RawJSON": base64::engine::general_purpose::STANDARD.encode(raw)
    });
    let (status, response) = call_plugin(
        "auth.parse",
        &serde_json::to_vec(&request).expect("invalid region request"),
    );
    assert_eq!(status, 0);
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "invalid_auth");
    assert_eq!(
        response["error"]["message"],
        "invalid Kiro region \"us-east-1.kiro.dev.evil\""
    );
}

#[test]
fn command_line_execute_without_login_flag_returns_unhandled_success() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    let fixture = fixture_json("executor.json");
    let request = serde_json::to_vec(&fixture["command_line"]["execute_unhandled"]["request"])
        .unwrap_or_else(|_| br#"{"TriggeredFlags":{}}"#.to_vec());
    let (status, response) = call_plugin("command_line.execute", &request);
    assert_eq!(status, 0);
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["ExitCode"], 0);
    assert_eq!(response["result"]["Stdout"], "");
}

#[test]
fn command_line_execute_login_requires_host_auth_directory() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    let request = br#"{"TriggeredFlags":{"kiro-login":{"Set":true}},"Host":{}}"#;
    let (status, response) = call_plugin("command_line.execute", request);
    assert_eq!(status, 0);
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["ExitCode"], 1);
    assert_eq!(
        response["result"]["Stderr"],
        base64::engine::general_purpose::STANDARD
            .encode("CLIProxyAPI did not provide an auth directory\n")
    );
}

#[test]
fn metadata_methods_expose_consumer_registration_contracts() {
    let _guard = COMPATIBILITY_TEST_LOCK
        .lock()
        .expect("compatibility test lock");
    restore_default_config();

    let (status, auth_identifier) = call_plugin("auth.identifier", b"");
    assert_eq!(status, 0);
    assert_eq!(auth_identifier["result"]["identifier"], "kiro");

    let (status, executor_identifier) = call_plugin("executor.identifier", b"");
    assert_eq!(status, 0);
    assert_eq!(executor_identifier["result"]["identifier"], "kiro");

    let expected = fixture_json("models.json");
    let (status, model_registration) = call_plugin("model.register", b"");
    assert_eq!(status, 0);
    assert_eq!(model_registration["result"]["Provider"], "kiro");
    assert_eq!(
        model_ids(&model_registration),
        expected["configured_model_ids"]
            .as_array()
            .expect("configured ids")
            .iter()
            .map(|id| id.as_str().expect("id"))
            .collect::<Vec<_>>()
    );

    let expected = fixture_json("executor.json");
    let (status, command_registration) = call_plugin("command_line.register", b"");
    assert_eq!(status, 0);
    assert_eq!(
        command_registration["result"]["Flags"],
        expected["command_line"]["register"]["response"]["result"]["Flags"]
    );
}
