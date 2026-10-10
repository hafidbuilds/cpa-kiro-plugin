//! Kiro plugin configuration parsing and model normalization.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};

/// Default Kiro plugin settings preserved from the Go implementation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct KiroPluginConfig {
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Configured Kiro model IDs; `*` exposes the default configured models.
    pub models: Vec<String>,
    /// Kiro client version sent in compatibility headers.
    pub kiro_version: String,
    /// Node.js version sent in compatibility headers.
    pub node_version: String,
    /// System version sent in compatibility headers.
    pub system_version: String,
}

impl Default for KiroPluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            models: vec!["claude-sonnet-4.5".into(), "claude-haiku-4.5".into()],
            kiro_version: "0.11.107".into(),
            node_version: "22.22.0".into(),
            system_version: "linux#6.6.87".into(),
        }
    }
}

static CURRENT_CONFIG: LazyLock<RwLock<KiroPluginConfig>> =
    LazyLock::new(|| RwLock::new(KiroPluginConfig::default()));

/// Parses CPA lifecycle JSON and stores normalized Kiro YAML settings.
pub fn configure_kiro_plugin(request: &[u8]) -> Result<(), String> {
    #[derive(Deserialize)]
    struct LifecycleRequest {
        #[serde(default)]
        config_yaml: String,
    }
    let request = if request.is_empty() {
        LifecycleRequest {
            config_yaml: String::new(),
        }
    } else {
        serde_json::from_slice(request)
            .map_err(|error| format!("decode plugin configuration: {error}"))?
    };
    let config_yaml = base64::engine::general_purpose::STANDARD
        .decode(request.config_yaml)
        .map_err(|error| format!("decode plugin configuration YAML: {error}"))?;
    let mut config = KiroPluginConfig::default();
    if !config_yaml.is_empty() {
        let yaml: KiroPluginConfig = serde_yaml::from_slice(&config_yaml)
            .map_err(|error| format!("decode Kiro plugin YAML: {error}"))?;
        config = yaml;
    }
    config.kiro_version = non_empty_or_default(&config.kiro_version, "0.11.107");
    config.node_version = non_empty_or_default(&config.node_version, "22.22.0");
    config.system_version = non_empty_or_default(&config.system_version, "linux#6.6.87");
    config.models = normalize_kiro_model_ids(&config.models);
    if config.models.is_empty() {
        config.models = KiroPluginConfig::default().models;
    }
    let mut stored = CURRENT_CONFIG
        .write()
        .map_err(|_| "Kiro config lock poisoned".to_string())?;
    *stored = config;
    Ok(())
}

/// Returns a snapshot of the normalized Kiro plugin settings.
pub fn loaded_kiro_config() -> KiroPluginConfig {
    CURRENT_CONFIG
        .read()
        .map(|config| config.clone())
        .unwrap_or_default()
}

/// Removes blank and duplicate configured Kiro model IDs without changing spelling.
pub fn normalize_kiro_model_ids(models: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(models.len());
    for model in models {
        let model = model.trim();
        if !model.is_empty() && !normalized.iter().any(|existing| existing == model) {
            normalized.push(model.to_string());
        }
    }
    normalized
}

fn non_empty_or_default(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_kiro_model_ids;

    #[test]
    fn normalize_kiro_model_ids_removes_blanks_and_duplicates_without_lowercasing() {
        let models = vec![
            " claude-sonnet-4.5 ".to_owned(),
            String::new(),
            "claude-sonnet-4.5".to_owned(),
            "Claude-Haiku-4.5".to_owned(),
        ];

        assert_eq!(
            normalize_kiro_model_ids(&models),
            ["claude-sonnet-4.5", "Claude-Haiku-4.5"]
        );
    }
}
