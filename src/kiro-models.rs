//! Kiro account model discovery through CPA host HTTP transport.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};

use crate::abi::invoke_host_json;
use crate::config::loaded_kiro_config;
use crate::kiro_credentials::parse_kiro_credential;
fn encode_query_value(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

const MODEL_DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(300);
struct CachedKiroModelResponse {
    inserted: Instant,
    response: Vec<u8>,
}
static MODEL_DISCOVERY_CACHE: LazyLock<Mutex<HashMap<String, CachedKiroModelResponse>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Discovers account models and applies cache, fallback, and configured filtering.
pub fn discover_kiro_models(request: &[u8]) -> Result<Vec<u8>, String> {
    let Some(key) = model_discovery_cache_key(request) else {
        return Ok(configured_model_fallback_response(
            "invalid discovery request",
        ));
    };
    if let Ok(cache) = MODEL_DISCOVERY_CACHE.lock() {
        if let Some(entry) = cache.get(&key) {
            if entry.inserted.elapsed() < MODEL_DISCOVERY_CACHE_TTL {
                return Ok(entry.response.clone());
            }
        }
    }
    match discover_kiro_models_remote(request) {
        Ok(response) => {
            if let Ok(mut cache) = MODEL_DISCOVERY_CACHE.lock() {
                cache.insert(
                    key,
                    CachedKiroModelResponse {
                        inserted: Instant::now(),
                        response: response.clone(),
                    },
                );
            }
            Ok(response)
        }
        Err(error) => {
            log_model_discovery_fallback(request, &error);
            if let Ok(cache) = MODEL_DISCOVERY_CACHE.lock() {
                if let Some(entry) = cache.get(&key) {
                    return Ok(entry.response.clone());
                }
            }
            Ok(configured_model_fallback_response(&error))
        }
    }
}

fn log_model_discovery_fallback(request: &[u8], error: &str) {
    let Ok(input) = serde_json::from_slice::<Value>(request) else {
        return;
    };
    let payload = json!({
        "host_callback_id": input.get("host_callback_id").and_then(Value::as_str).unwrap_or_default(),
        "level": "warn",
        "message": "Kiro model discovery failed; using cached or configured models",
        "fields": {
            "auth_id": input.get("auth_id").and_then(Value::as_str).unwrap_or_default(),
            "error": error
        }
    });
    if let Ok(raw) = serde_json::to_vec(&payload) {
        let _ = invoke_host_json("host.log", &raw);
    }
}
fn model_discovery_cache_key(request: &[u8]) -> Option<String> {
    let input: Value = serde_json::from_slice(request).ok()?;
    let storage = input.get("storage_json")?;
    let raw_storage = if let Some(encoded) = storage.as_str() {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?
    } else {
        serde_json::to_vec(storage).ok()?
    };
    let credential = parse_kiro_credential(&raw_storage).ok()??;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    raw_storage.hash(&mut hasher);
    Some(format!(
        "{}:{}:{}",
        input
            .get("auth_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        credential.runtime_region(),
        hasher.finish()
    ))
}

fn discover_kiro_models_remote(request: &[u8]) -> Result<Vec<u8>, String> {
    let input: Value = serde_json::from_slice(request)
        .map_err(|error| format!("decode Kiro model request: {error}"))?;
    let storage = input
        .get("storage_json")
        .ok_or_else(|| "Kiro model request has no storage_json".to_string())?;
    let storage = if let Some(encoded) = storage.as_str() {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| error.to_string())?
    } else {
        serde_json::to_vec(storage).map_err(|error| error.to_string())?
    };
    let credential = parse_kiro_credential(&storage)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Kiro credential was not recognized".to_string())?;
    let runtime_region = credential.runtime_region();
    let host = if runtime_region == "us-east-1" {
        "codewhisperer.us-east-1.amazonaws.com".to_owned()
    } else {
        format!("q.{runtime_region}.amazonaws.com")
    };
    let token = credential
        .bearer_token()
        .map_err(|error| error.to_string())?;
    let mut next_token = String::new();
    let mut seen_tokens = std::collections::HashSet::new();
    let mut models = Vec::new();
    for _ in 0..10 {
        let mut url = format!("https://{host}/ListAvailableModels?origin=AI_EDITOR&maxResults=50");
        if !credential.profile_arn.is_empty() {
            url.push_str("&profileArn=");
            url.push_str(&encode_query_value(&credential.profile_arn));
        }
        if !next_token.is_empty() {
            url.push_str("&nextToken=");
            url.push_str(&encode_query_value(&next_token));
        }
        let callback_request = json!({
            "host_callback_id": input.get("host_callback_id").and_then(Value::as_str).unwrap_or_default(),
            "method": "GET",
            "url": url,
            "headers": {"Authorization": [format!("Bearer {token}")]}
        });
        let raw = invoke_host_json(
            "host.http.do",
            &serde_json::to_vec(&callback_request).map_err(|error| error.to_string())?,
        )?;
        let response: Value = serde_json::from_slice(&raw)
            .map_err(|error| format!("decode Kiro model HTTP response: {error}"))?;
        let status = response
            .get("StatusCode")
            .or_else(|| response.get("status_code"))
            .and_then(Value::as_i64)
            .unwrap_or(500);
        if status != 200 {
            return Err(format!("Kiro model-list endpoint returned HTTP {status}"));
        }
        let body = response
            .get("Body")
            .or_else(|| response.get("body"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let body = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|error| error.to_string())?;
        let listing: Value = serde_json::from_slice(&body)
            .map_err(|error| format!("decode Kiro model-list response: {error}"))?;
        models.extend(
            listing
                .get("models")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .cloned(),
        );
        next_token = listing
            .get("nextToken")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if next_token.is_empty() {
            break;
        }
        if !seen_tokens.insert(next_token.clone()) {
            return Err("Kiro model-list pagination repeated a next token".into());
        }
    }
    let configured = loaded_kiro_config().models;
    let allow_all = configured.iter().any(|model| model == "*");
    let mut seen_models = std::collections::HashSet::new();
    let models = models
        .into_iter()
        .filter_map(|model| {
            let id = model
                .get("modelId")
                .or_else(|| model.get("model_id"))
                .and_then(Value::as_str)?
                .trim()
                .to_owned();
            if id.is_empty()
                || !seen_models.insert(id.to_ascii_lowercase())
                || (!allow_all && !configured.iter().any(|allowed| allowed == &id))
            {
                return None;
            }
            let display_name = model
                .get("modelName")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(&id)
                .trim();
            let token_limits = model.get("tokenLimits");
            let input_limit = token_limits
                .and_then(|limits| limits.get("maxInputTokens"))
                .and_then(Value::as_i64)
                .filter(|limit| *limit > 0)
                .unwrap_or(200_000);
            let output_limit = token_limits
                .and_then(|limits| limits.get("maxOutputTokens"))
                .and_then(Value::as_i64)
                .filter(|limit| *limit > 0)
                .unwrap_or(64_000);
            let input_types = model.get("supportedInputTypes").and_then(Value::as_array);
            let mut modalities = Vec::new();
            if let Some(input_types) = input_types {
                for input_type in input_types.iter().filter_map(Value::as_str) {
                    let modality = match input_type.trim().to_ascii_uppercase().as_str() {
                        "TEXT" => "text",
                        "IMAGE" => "image",
                        _ => continue,
                    };
                    if !modalities.contains(&modality) {
                        modalities.push(modality);
                    }
                }
            }
            if modalities.is_empty() {
                modalities.push("text");
            }
            let mut info = json!({
                "ID": id, "Name": display_name, "DisplayName": display_name, "Object": "model",
                "OwnedBy": "kiro", "Type": "claude", "ContextLength": input_limit,
                "InputTokenLimit": input_limit, "OutputTokenLimit": output_limit,
                "MaxCompletionTokens": output_limit,
                "SupportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "SupportedParameters": ["max_tokens", "temperature", "top_p", "tools"],
                "SupportedInputModalities": modalities, "SupportedOutputModalities": ["text"]
            });
            if let Some(description) = model
                .get("description")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|description| !description.is_empty())
            {
                info["Description"] = json!(description);
            }
            Some(info)
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"ok": true, "result": {"Provider": "kiro", "Models": models}})
            .to_string()
            .into_bytes(),
    )
}

fn configured_model_fallback_response(error: &str) -> Vec<u8> {
    let configured = loaded_kiro_config().models;
    let configured = if configured.iter().any(|model| model == "*") {
        vec![
            "claude-sonnet-4.5".to_owned(),
            "claude-haiku-4.5".to_owned(),
        ]
    } else {
        configured
    };
    let models = configured
        .into_iter()
        .filter(|model| !model.is_empty())
        .map(|id| {
            json!({
                "ID": id, "Name": id, "DisplayName": id, "Object": "model",
                "OwnedBy": "kiro", "Type": "claude", "ContextLength": 200000,
                "InputTokenLimit": 200000, "OutputTokenLimit": 64000,
                "MaxCompletionTokens": 64000,
                "SupportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "SupportedParameters": ["max_tokens", "temperature", "top_p", "tools"],
                "SupportedInputModalities": ["text", "image"],
                "SupportedOutputModalities": ["text"]
            })
        })
        .collect::<Vec<_>>();
    json!({
        "ok": true,
        "result": {"Provider": "kiro", "Models": models},
        "metadata": {"discovery_fallback": true, "error": error}
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use std::ffi::{c_void, CStr};
    use std::ptr;
    use std::slice;
    use std::sync::Mutex;

    use base64::Engine;
    use serde_json::Value;

    static MODEL_TEST_LOCK: Mutex<()> = Mutex::new(());

    use super::{configured_model_fallback_response, discover_kiro_models, encode_query_value};
    use crate::abi::{cliproxy_buffer, cliproxy_host_api, cliproxy_plugin_api, initialize_plugin};

    unsafe extern "C" fn paginated_model_list_host_call(
        _ctx: *mut c_void,
        method: *const std::ffi::c_char,
        request: *const u8,
        request_len: usize,
        response: *mut cliproxy_buffer,
    ) -> i32 {
        let method = unsafe { CStr::from_ptr(method) }.to_string_lossy();
        let request = if request.is_null() || request_len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(request, request_len) }
        };
        let body = if method == "host.http.do" {
            let request: Value = serde_json::from_slice(request).unwrap_or(Value::Null);
            let url = request.get("url").and_then(Value::as_str).unwrap_or("");
            let listing = if url.contains("nextToken=") {
                serde_json::json!({
                    "models": [
                        {"modelId": "claude-opus-5", "modelName": "duplicate"},
                        {"modelId": "glm-5", "modelName": "GLM 5"}
                    ]
                })
            } else {
                serde_json::json!({
                    "models": [
                        {"modelId": "claude-opus-5", "modelName": "Claude Opus 5"},
                        {"modelId": "", "modelName": "invalid"}
                    ],
                    "nextToken": "page +/="
                })
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(listing.to_string());
            serde_json::json!({"ok": true, "result": {"StatusCode": 200, "Body": encoded}})
        } else {
            serde_json::json!({"ok": true, "result": {}})
        };
        let raw = body.to_string().into_bytes();
        if !response.is_null() && !raw.is_empty() {
            let mut owned = raw.into_boxed_slice();
            unsafe {
                (*response).ptr = owned.as_mut_ptr();
                (*response).len = owned.len();
            }
            std::mem::forget(owned);
        }
        0
    }

    fn install_paginated_model_list_host() {
        let host = cliproxy_host_api {
            abi_version: 1,
            host_ctx: ptr::null_mut(),
            call: Some(paginated_model_list_host_call),
            free_buffer: None,
        };
        let mut plugin = cliproxy_plugin_api {
            abi_version: 0,
            call: None,
            free_buffer: None,
            shutdown: None,
        };
        assert_eq!(unsafe { initialize_plugin(&host, &mut plugin) }, 0);
    }

    fn configure_from_yaml(yaml: &str) {
        let request = serde_json::json!({
            "config_yaml": base64::engine::general_purpose::STANDARD.encode(yaml)
        });
        crate::config::configure_kiro_plugin(request.to_string().as_bytes())
            .expect("valid plugin configuration");
    }

    fn discovered_model_ids(auth_id: &str) -> Vec<String> {
        std::env::set_var("KIRO_TEST_KEY", "REDACTED_API_KEY");
        let request = serde_json::json!({
            "auth_id": auth_id,
            "storage_json": {
                "type": "kiro",
                "api_key_env": "KIRO_TEST_KEY",
                "region": "us-east-1"
            },
            "host_callback_id": "callback-1"
        });
        let response = discover_kiro_models(request.to_string().as_bytes()).expect("discovery");
        let response: Value = serde_json::from_slice(&response).expect("discovery JSON");
        response
            .pointer("/result/Models")
            .and_then(Value::as_array)
            .expect("models")
            .iter()
            .map(|model| model["ID"].as_str().expect("model ID").to_owned())
            .collect()
    }

    #[test]
    fn model_discovery_query_values_escape_reserved_bytes() {
        assert_eq!(
            encode_query_value("arn:aws/example profile"),
            "arn%3Aaws%2Fexample%20profile"
        );
    }

    #[test]
    fn wildcard_discovery_fallback_returns_default_models() {
        let response = configured_model_fallback_response("unavailable");
        let response: Value = serde_json::from_slice(&response).expect("fallback response JSON");
        let models = response
            .pointer("/result/Models")
            .and_then(Value::as_array)
            .expect("models");
        assert_eq!(models.len(), 2);
        assert_eq!(models[0]["ID"], "claude-sonnet-4.5");
        assert_eq!(models[1]["ID"], "claude-haiku-4.5");
        assert_eq!(response["metadata"]["discovery_fallback"], true);
        assert_eq!(response["metadata"]["error"], "unavailable");
    }

    #[test]
    fn allowlist_discovery_fallback_returns_configured_model_ids() {
        let _guard = MODEL_TEST_LOCK.lock().expect("model test lock");
        let yaml = serde_json::json!({
            "config_yaml": base64::engine::general_purpose::STANDARD.encode(
                "enabled: true\nmodels: [\"claude-haiku-4.5\"]\n"
            )
        });
        crate::config::configure_kiro_plugin(yaml.to_string().as_bytes())
            .expect("allowlist configuration");

        let response = configured_model_fallback_response("unavailable");
        let response: Value = serde_json::from_slice(&response).expect("fallback response JSON");
        let models = response
            .pointer("/result/Models")
            .and_then(Value::as_array)
            .expect("models");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0]["ID"], "claude-haiku-4.5");
        assert_eq!(models[0]["OwnedBy"], "kiro");
        crate::config::configure_kiro_plugin(b"").expect("restore defaults");
    }

    #[test]
    fn wildcard_discovery_keeps_unique_nonempty_upstream_ids() {
        let _guard = MODEL_TEST_LOCK.lock().expect("model test lock");
        install_paginated_model_list_host();
        configure_from_yaml(
            "enabled: true\nmodels: [\"*\"]\nkiro_version: \"0.11.107\"\nnode_version: \"22.22.0\"\nsystem_version: \"linux#6.6.87\"\n",
        );
        let ids = discovered_model_ids("compat-wildcard-discovery");
        crate::abi::shutdown_plugin();
        crate::config::configure_kiro_plugin(b"").expect("restore defaults");
        assert_eq!(ids, ["claude-opus-5", "glm-5"]);
    }

    #[test]
    fn allowlist_discovery_drops_unconfigured_upstream_ids() {
        let _guard = MODEL_TEST_LOCK.lock().expect("model test lock");
        install_paginated_model_list_host();
        configure_from_yaml(
            "enabled: true\nmodels: [\"claude-opus-5\"]\nkiro_version: \"0.11.107\"\nnode_version: \"22.22.0\"\nsystem_version: \"linux#6.6.87\"\n",
        );
        let ids = discovered_model_ids("compat-allowlist-discovery");
        crate::abi::shutdown_plugin();
        crate::config::configure_kiro_plugin(b"").expect("restore defaults");
        assert_eq!(ids, ["claude-opus-5"]);
    }
}
