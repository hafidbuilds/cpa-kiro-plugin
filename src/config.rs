//! Kiro plugin configuration parsing and model normalization.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

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
    /// Minimum gap between two upstream requests of one credential.
    pub min_token_interval: String,
    /// Upper bound of that gap, and of how long a request may queue for it.
    pub max_token_interval: String,
    /// How long a suspended credential stays out of rotation.
    pub suspend_cooldown: String,
}

/// Parsed per-credential pacing settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KiroPacingConfig {
    /// Minimum gap between two requests of one credential.
    pub min_interval: Duration,
    /// Maximum gap, and the longest a request waits before failing over.
    pub max_interval: Duration,
    /// How long a suspended credential is benched.
    pub suspend_cooldown: Duration,
}

impl KiroPluginConfig {
    /// Parses the pacing durations (`500ms`, `1s`, `5m`, `1h`).
    pub fn pacing(&self) -> Result<KiroPacingConfig, String> {
        let min_interval = parse_duration("min_token_interval", &self.min_token_interval)?;
        let max_interval = parse_duration("max_token_interval", &self.max_token_interval)?;
        if max_interval < min_interval {
            return Err("max_token_interval must not be shorter than min_token_interval".into());
        }
        Ok(KiroPacingConfig {
            min_interval,
            max_interval,
            suspend_cooldown: parse_duration("suspend_cooldown", &self.suspend_cooldown)?,
        })
    }
}

fn parse_duration(name: &str, value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let split = value
        .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let number: f64 = number
        .parse()
        .map_err(|_| format!("{name}: invalid duration {value:?}"))?;
    let seconds = match unit {
        "ms" => number / 1000.0,
        "s" => number,
        "m" => number * 60.0,
        "h" => number * 3600.0,
        _ => {
            return Err(format!(
                "{name}: duration {value:?} needs a unit of ms, s, m or h"
            ))
        }
    };
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(format!("{name}: invalid duration {value:?}"));
    }
    Ok(Duration::from_secs_f64(seconds))
}

impl Default for KiroPluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            models: vec!["claude-sonnet-4.5".into(), "claude-haiku-4.5".into()],
            kiro_version: "1.4.5".into(),
            node_version: "22.22.0".into(),
            system_version: "darwin#24.6.0".into(),
            min_token_interval: "1s".into(),
            max_token_interval: "2s".into(),
            suspend_cooldown: "1h".into(),
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
    config.kiro_version = non_empty_or_default(&config.kiro_version, "1.4.5");
    config.node_version = non_empty_or_default(&config.node_version, "22.22.0");
    config.system_version = non_empty_or_default(&config.system_version, "darwin#24.6.0");
    let defaults = KiroPluginConfig::default();
    config.min_token_interval =
        non_empty_or_default(&config.min_token_interval, &defaults.min_token_interval);
    config.max_token_interval =
        non_empty_or_default(&config.max_token_interval, &defaults.max_token_interval);
    config.suspend_cooldown =
        non_empty_or_default(&config.suspend_cooldown, &defaults.suspend_cooldown);
    config.pacing()?;
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
    use super::{normalize_kiro_model_ids, KiroPluginConfig};
    use std::time::Duration;

    #[test]
    fn pacing_defaults_match_kiro4cpa() {
        let pacing = KiroPluginConfig::default()
            .pacing()
            .expect("default pacing");
        assert_eq!(pacing.min_interval, Duration::from_secs(1));
        assert_eq!(pacing.max_interval, Duration::from_secs(2));
        assert_eq!(pacing.suspend_cooldown, Duration::from_secs(3600));
    }

    #[test]
    fn pacing_rejects_unitless_and_inverted_intervals() {
        let mut config = KiroPluginConfig {
            min_token_interval: "1".into(),
            ..KiroPluginConfig::default()
        };
        assert!(config.pacing().is_err());
        config.min_token_interval = "3s".into();
        config.max_token_interval = "500ms".into();
        assert!(config.pacing().is_err());
        config.min_token_interval = "250ms".into();
        assert_eq!(
            config.pacing().expect("valid").min_interval,
            Duration::from_millis(250)
        );
    }

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
