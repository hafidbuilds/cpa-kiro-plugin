//! Kiro credential parsing, classification, and token selection.
//!
//! This module keeps the credential-file contract independent of the host HTTP
//! transport. OAuth records retain the fields needed by a later refresh and
//! runtime request implementation.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};

/// Credential provider identifier written into Kiro auth files.
pub const KIRO_PLUGIN_IDENTIFIER: &str = "kiro";
/// Builder ID start URL used when login metadata omits a method.
pub const BUILDER_ID_START_URL: &str = "https://view.awsapps.com/start";
/// Fixed CodeWhisperer profile ARN for AWS Builder ID accounts.
pub const BUILDER_ID_PROFILE_ARN: &str =
    "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX";
const DEFAULT_KIRO_REGION: &str = "us-east-1";
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(5 * 60);
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_TOKEN_LIFETIME_SECS: i64 = 3600;

/// Authentication method recorded in a Kiro credential file.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum KiroAuthMethod {
    /// A static API key, optionally loaded from an environment variable.
    #[default]
    ApiKey,
    /// AWS IAM Identity Center (AWS SSO) OAuth credentials.
    Idc,
    /// Kiro desktop OAuth credentials.
    Desktop,
    /// OAuth credentials issued by an external identity provider.
    ExternalIdp,
}

impl KiroAuthMethod {
    /// Returns the credential-file spelling used for this authentication method.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "apikey",
            Self::Idc => "idc",
            Self::Desktop => "desktop",
            Self::ExternalIdp => "external-idp",
        }
    }

    /// Returns whether this method carries refreshable OAuth credentials.
    pub const fn is_oauth(self) -> bool {
        !matches!(self, Self::ApiKey)
    }

    fn parse(value: &str) -> Result<Self, KiroCredentialError> {
        match value {
            "apikey" => Ok(Self::ApiKey),
            "idc" => Ok(Self::Idc),
            "desktop" => Ok(Self::Desktop),
            "external-idp" => Ok(Self::ExternalIdp),
            other => Err(KiroCredentialError::UnsupportedAuthMethod(other.to_owned())),
        }
    }
}

impl Serialize for KiroAuthMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KiroAuthMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value.trim().to_ascii_lowercase().as_str()).map_err(serde::de::Error::custom)
    }
}

/// High-level credential family used in host metadata and request handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KiroCredentialKind {
    /// A static API key credential.
    ApiKey,
    /// Any supported OAuth credential family.
    OAuth,
}

/// A parsed Kiro credential-file record.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case", default)]
pub struct KiroCredential {
    /// Credential provider identifier; supported records use `kiro`.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub credential_type: String,
    /// Kiro authentication method; omitted legacy records are API keys.
    pub auth_method: KiroAuthMethod,
    /// Inline API key, if present.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    /// Environment variable name containing the API key, if present.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub api_key_env: String,
    /// Login region, or the AWS SSO OIDC region for IDC credentials.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// Kiro profile ARN associated with an OAuth account.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_arn: String,
    /// OAuth access token used as the runtime bearer token.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub access_token: String,
    /// OAuth refresh token used by the refresh implementation.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
    /// RFC3339 access-token expiry timestamp.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub expired: String,
    /// OAuth client identifier for IDC and external-IdP records.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    /// OAuth client secret for IDC records.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    /// AWS IAM Identity Center start URL.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub start_url: String,
    /// HTTPS token endpoint for external-IdP credentials.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token_endpoint: String,
    /// Account email used as a display-label fallback.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub email: String,
    /// User-selected display label.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Host auth prefix metadata.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// Optional host proxy URL metadata.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proxy_url: String,
    /// Whether the host should skip this credential.
    #[serde(skip_serializing_if = "is_false")]
    pub disabled: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl KiroCredential {
    /// Returns the normalized credential family for host metadata.
    pub const fn kind(&self) -> KiroCredentialKind {
        if self.auth_method.is_oauth() {
            KiroCredentialKind::OAuth
        } else {
            KiroCredentialKind::ApiKey
        }
    }

    /// Returns whether this record contains OAuth credentials.
    pub const fn is_oauth(&self) -> bool {
        self.auth_method.is_oauth()
    }

    /// Returns the profile's runtime region, preferring the profile ARN region.
    pub fn runtime_region(&self) -> String {
        region_from_profile_arn(&self.profile_arn)
            .unwrap_or_else(|| api_region(&self.region).to_owned())
    }

    /// Returns the token sent in the runtime `Authorization: Bearer` header.
    pub fn bearer_token(&self) -> Result<String, KiroCredentialError> {
        if self.is_oauth() {
            if self.access_token.is_empty() {
                return Err(KiroCredentialError::ApiKeyUnavailable(
                    "OAuth access token is empty".to_owned(),
                ));
            }
            return Ok(self.access_token.clone());
        }
        if !self.api_key.is_empty() {
            return Ok(self.api_key.clone());
        }
        let key = env::var(self.api_key_env.as_str())
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        key.ok_or_else(|| {
            KiroCredentialError::ApiKeyUnavailable(format!(
                "environment variable {} is empty",
                self.api_key_env
            ))
        })
    }

    /// Returns the refresh cadence derived from the expiry timestamp.
    ///
    /// Invalid or missing timestamps return `None`. Valid timestamps are
    /// refreshed five minutes before expiry, with a one-minute minimum cadence.
    pub fn refresh_interval(&self) -> Option<Duration> {
        let expiry = parse_rfc3339(self.expired.as_str())?;
        let remaining = expiry.duration_since(SystemTime::now()).ok();
        Some(match remaining {
            Some(remaining) if remaining > TOKEN_REFRESH_SKEW => {
                remaining.saturating_sub(TOKEN_REFRESH_SKEW)
            }
            _ => MIN_REFRESH_INTERVAL,
        })
    }

    /// Validates and normalizes a decoded credential record.
    pub fn validate(mut self) -> Result<Self, KiroCredentialError> {
        self.credential_type = self.credential_type.trim().to_ascii_lowercase();
        if self.credential_type != KIRO_PLUGIN_IDENTIFIER {
            return Err(KiroCredentialError::WrongProvider(self.credential_type));
        }
        self.region = if self.region.trim().is_empty() {
            DEFAULT_KIRO_REGION.to_owned()
        } else {
            self.region.trim().to_ascii_lowercase()
        };
        self.api_key = self.api_key.trim().to_owned();
        self.api_key_env = self.api_key_env.trim().to_owned();
        self.profile_arn = self.profile_arn.trim().to_owned();
        self.access_token = self.access_token.trim().to_owned();
        self.refresh_token = self.refresh_token.trim().to_owned();
        self.expired = self.expired.trim().to_owned();
        self.client_id = self.client_id.trim().to_owned();
        self.client_secret = self.client_secret.trim().to_owned();
        self.token_endpoint = self.token_endpoint.trim().to_owned();
        self.label = self.label.trim().to_owned();
        self.prefix = self.prefix.trim().to_owned();
        self.proxy_url = self.proxy_url.trim().to_owned();

        if !is_valid_kiro_region(&self.region) {
            return Err(KiroCredentialError::InvalidRegion(self.region));
        }
        if !self.profile_arn.is_empty() && region_from_profile_arn(&self.profile_arn).is_none() {
            return Err(KiroCredentialError::InvalidProfileArn);
        }
        match self.auth_method {
            KiroAuthMethod::ApiKey => {
                if self.api_key.is_empty() && self.api_key_env.is_empty() {
                    return Err(KiroCredentialError::MissingApiKey);
                }
                if self.api_key_env.contains('=') {
                    return Err(KiroCredentialError::InvalidApiKeyEnvironment);
                }
            }
            KiroAuthMethod::Idc => {
                if self.client_id.is_empty() || self.client_secret.is_empty() {
                    return Err(KiroCredentialError::MissingIdcClientCredentials);
                }
            }
            KiroAuthMethod::Desktop => {}
            KiroAuthMethod::ExternalIdp => {
                if self.client_id.is_empty() {
                    return Err(KiroCredentialError::MissingExternalIdpClientId);
                }
                if !is_https_endpoint(&self.token_endpoint) {
                    return Err(KiroCredentialError::InvalidExternalIdpEndpoint);
                }
            }
        }
        if self.is_oauth() && self.access_token.is_empty() && self.refresh_token.is_empty() {
            return Err(KiroCredentialError::MissingOAuthTokens);
        }
        Ok(self)
    }

    /// Applies a token-endpoint response, keeping a previous refresh token or profile ARN when omitted.
    pub fn apply_oauth_tokens(
        &mut self,
        access_token: &str,
        refresh_token: &str,
        expires_in: i64,
        profile_arn: &str,
    ) -> Result<(), KiroCredentialError> {
        let access_token = access_token.trim();
        if access_token.is_empty() {
            return Err(KiroCredentialError::MissingAccessToken);
        }
        self.access_token = access_token.to_owned();
        let refresh_token = refresh_token.trim();
        if !refresh_token.is_empty() {
            self.refresh_token = refresh_token.to_owned();
        }
        let profile_arn = profile_arn.trim();
        if !profile_arn.is_empty() {
            self.profile_arn = profile_arn.to_owned();
        }
        let lifetime = if expires_in > 0 {
            expires_in
        } else {
            DEFAULT_TOKEN_LIFETIME_SECS
        };
        let expiry = OffsetDateTime::now_utc() + TimeDuration::seconds(lifetime);
        self.expired = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            expiry.year(),
            u8::from(expiry.month()),
            expiry.day(),
            expiry.hour(),
            expiry.minute(),
            expiry.second()
        );
        Ok(())
    }

    /// Returns the stable, non-secret identifier used in labels and auth file names.
    pub fn fingerprint(&self) -> String {
        let seed = if self.is_oauth() {
            format!(
                "oauth:{}",
                first_non_empty(&[&self.profile_arn, &self.email, &self.refresh_token])
            )
        } else if !self.api_key.is_empty() {
            self.api_key.clone()
        } else {
            format!("env:{}", self.api_key_env)
        };
        let digest = Sha256::digest(format!("KiroAPIKey/{seed}").as_bytes());
        hex_encode(&digest[..6])
    }

    /// Names the persisted auth file after the method and fingerprint.
    pub fn credential_file_name(&self) -> String {
        format!(
            "kiro-{}-{}.json",
            self.auth_method.as_str(),
            self.fingerprint()
        )
    }

    /// Builds the host auth record used by parse, login, and refresh responses.
    pub fn host_auth_data(
        &self,
        auth_id: &str,
        file_name: &str,
    ) -> Result<Value, KiroCredentialError> {
        let storage = serde_json::to_vec(self).map_err(|error| {
            KiroCredentialError::Decode(format!("encode Kiro credential: {error}"))
        })?;
        let file_stem = file_name
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(file_name);
        let label = first_non_empty(&[&self.label, &self.email, file_stem, &self.fingerprint()]);
        let mut metadata = Map::new();
        metadata.insert("type".into(), json!(KIRO_PLUGIN_IDENTIFIER));
        metadata.insert("auth_method".into(), json!(self.auth_method.as_str()));
        metadata.insert("region".into(), json!(self.region));
        let mut attributes = Map::new();
        attributes.insert("auth_method".into(), json!(self.auth_method.as_str()));
        attributes.insert("region".into(), json!(self.region));
        if self.is_oauth() {
            metadata.insert("auth_kind".into(), json!("oauth"));
            attributes.insert("auth_kind".into(), json!("oauth"));
            metadata.insert("access_token".into(), json!(self.access_token));
            metadata.insert("refresh_token".into(), json!(self.refresh_token));
            if !self.expired.is_empty() {
                metadata.insert("expired".into(), json!(self.expired));
            }
            if !self.profile_arn.is_empty() {
                metadata.insert("profile_arn".into(), json!(self.profile_arn));
                attributes.insert("profile_arn".into(), json!(self.profile_arn));
            }
            if !self.email.is_empty() {
                metadata.insert("email".into(), json!(self.email));
            }
            if let Some(interval) = self.refresh_interval() {
                metadata.insert(
                    "refresh_interval_seconds".into(),
                    json!(interval.as_secs() as i64),
                );
            }
        } else {
            metadata.insert("auth_kind".into(), json!("api_key"));
            attributes.insert("auth_kind".into(), json!("api_key"));
            metadata.insert("key_source".into(), json!(self.key_source()));
            metadata.insert(
                "key_present".into(),
                json!(
                    !self.api_key.is_empty()
                        || env::var(&self.api_key_env).is_ok_and(|value| !value.is_empty())
                ),
            );
        }
        let mut auth = Map::new();
        auth.insert("Provider".into(), json!(KIRO_PLUGIN_IDENTIFIER));
        auth.insert("ID".into(), json!(auth_id));
        auth.insert("FileName".into(), json!(file_name));
        auth.insert("Label".into(), json!(label));
        if !self.prefix.is_empty() {
            auth.insert("Prefix".into(), json!(self.prefix));
        }
        if !self.proxy_url.is_empty() {
            auth.insert("ProxyURL".into(), json!(self.proxy_url));
        }
        if self.disabled {
            auth.insert("Disabled".into(), json!(true));
        }
        auth.insert(
            "StorageJSON".into(),
            json!(base64::engine::general_purpose::STANDARD.encode(storage)),
        );
        auth.insert("Metadata".into(), Value::Object(metadata));
        auth.insert("Attributes".into(), Value::Object(attributes));
        Ok(Value::Object(auth))
    }

    fn key_source(&self) -> String {
        if !self.api_key.is_empty() {
            "auth_file".to_owned()
        } else {
            format!("env:{}", self.api_key_env)
        }
    }
}

/// Errors found while decoding, validating, or selecting a Kiro credential.
#[derive(Debug, Error)]
pub enum KiroCredentialError {
    /// The JSON document was syntactically valid but belongs to another provider.
    #[error("credential belongs to provider {0:?}, not kiro")]
    WrongProvider(String),
    /// The region is not a Kiro/AWS region spelling accepted by the Go plugin.
    #[error("invalid Kiro region {0:?}")]
    InvalidRegion(String),
    /// The profile ARN is not a CodeWhisperer profile ARN with a valid region.
    #[error("invalid Kiro profile ARN")]
    InvalidProfileArn,
    /// API-key records must provide an inline key or environment variable.
    #[error("either api_key or api_key_env is required")]
    MissingApiKey,
    /// An API-key environment field must contain only a variable name.
    #[error("api_key_env must be an environment variable name")]
    InvalidApiKeyEnvironment,
    /// IDC records need both OAuth client credentials.
    #[error("idc credentials require client_id and client_secret")]
    MissingIdcClientCredentials,
    /// External-IdP records need an OAuth client ID.
    #[error("external-idp credentials require client_id")]
    MissingExternalIdpClientId,
    /// External-IdP token endpoints must be HTTPS URLs with a host.
    #[error("external-idp credentials require an https token_endpoint")]
    InvalidExternalIdpEndpoint,
    /// OAuth records need at least one token for runtime or refresh use.
    #[error("OAuth credentials require access_token or refresh_token")]
    MissingOAuthTokens,
    /// The auth method is not one of the supported Kiro methods.
    #[error("unsupported Kiro auth_method {0:?}")]
    UnsupportedAuthMethod(String),
    /// The runtime bearer token cannot be selected from this record.
    #[error("Kiro API key unavailable: {0}")]
    ApiKeyUnavailable(String),
    /// The credential JSON could not be decoded.
    #[error("decode Kiro credential: {0}")]
    Decode(String),
    /// A token endpoint omitted the access token required to continue.
    #[error("Kiro token response is missing an access token")]
    MissingAccessToken,
}

/// Parses one JSON credential record, returning `None` for unrelated JSON.
///
/// Malformed JSON also returns `None`, matching the frozen Go parser's behavior
/// for files that are not recognizable credential records.
pub fn parse_kiro_credential(raw: &[u8]) -> Result<Option<KiroCredential>, KiroCredentialError> {
    let value: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(provider) = object.get("type").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if provider.trim().to_ascii_lowercase() != KIRO_PLUGIN_IDENTIFIER {
        return Ok(None);
    }
    if let Some(method) = object.get("auth_method") {
        let method = method
            .as_str()
            .ok_or_else(|| KiroCredentialError::UnsupportedAuthMethod(method.to_string()))?;
        KiroAuthMethod::parse(method.trim().to_ascii_lowercase().as_str())?;
    }
    let mut credential: KiroCredential = serde_json::from_value(value)
        .map_err(|error| KiroCredentialError::Decode(error.to_string()))?;
    credential.credential_type = KIRO_PLUGIN_IDENTIFIER.to_owned();
    Ok(Some(credential.validate()?))
}
/// Returns whether a region matches Kiro's lowercase AWS region format.
pub fn is_valid_kiro_region(region: &str) -> bool {
    let parts: Vec<&str> = region.split('-').collect();
    let valid_letters = |value: &str, minimum: usize| {
        value.len() >= minimum && value.bytes().all(|byte| byte.is_ascii_lowercase())
    };
    match parts.as_slice() {
        [country, area, number] => {
            country.len() == 2
                && valid_letters(country, 2)
                && valid_letters(area, 1)
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        }
        [country, government, area, number] => {
            country.len() == 2
                && valid_letters(country, 2)
                && *government == "gov"
                && valid_letters(area, 1)
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

/// Management regions probed while discovering a Kiro profile ARN.
pub const KIRO_MANAGEMENT_REGIONS: [&str; 2] = ["us-east-1", "eu-central-1"];

/// Returns management regions with the credential's API region first.
pub fn candidate_management_regions(primary: &str) -> Vec<String> {
    let mut regions = vec![primary.to_owned()];
    for region in KIRO_MANAGEMENT_REGIONS {
        if region != primary {
            regions.push(region.to_owned());
        }
    }
    regions
}

/// Maps AWS login regions to Kiro's canonical API regions.
pub fn api_region(region: &str) -> &str {
    match region {
        "sa-east-1" | "us-west-1" | "us-west-2" | "us-east-2" | "ap-southeast-1"
        | "ap-southeast-2" | "ap-northeast-1" | "ap-northeast-2" | "ap-south-1" => "us-east-1",
        "eu-west-1" | "eu-west-2" | "eu-west-3" | "eu-north-1" | "eu-south-1" | "eu-south-2"
        | "eu-central-2" => "eu-central-1",
        "" => DEFAULT_KIRO_REGION,
        other => other,
    }
}

/// Extracts a valid region from a CodeWhisperer profile ARN.
pub fn region_from_profile_arn(arn: &str) -> Option<String> {
    let parts: Vec<&str> = arn.trim().split(':').collect();
    let region = parts.get(3).copied()?;
    if parts.len() < 6 || parts[0] != "arn" || parts[2] != "codewhisperer" {
        return None;
    }
    is_valid_kiro_region(region).then(|| region.to_owned())
}

fn first_non_empty(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or("")
        .to_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn is_https_endpoint(endpoint: &str) -> bool {
    let Some(authority) = endpoint.strip_prefix("https://") else {
        return false;
    };
    let host = authority.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty() && !host.chars().any(char::is_whitespace)
}

fn parse_rfc3339(value: &str) -> Option<SystemTime> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    if bytes.get(10) != Some(&b'T') && bytes.get(10) != Some(&b't') {
        return None;
    }
    if bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') {
        return None;
    }
    let year = parse_digits(bytes, 0, 4)? as i64;
    let month = parse_digits(bytes, 5, 7)? as i64;
    let day = parse_digits(bytes, 8, 10)? as i64;
    let hour = parse_digits(bytes, 11, 13)? as i64;
    let minute = parse_digits(bytes, 14, 16)? as i64;
    let second = parse_digits(bytes, 17, 19)? as i64;
    if month == 0 || month > 12 || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut index = 19;
    let nanos = if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return None;
        }
        let mut nanos = 0_u32;
        for byte in &bytes[start..index.min(start + 9)] {
            nanos = nanos * 10 + u32::from(byte - b'0');
        }
        nanos * 10_u32.pow(9_u32.saturating_sub((index - start).min(9) as u32))
    } else {
        0
    };
    let offset_seconds = match bytes.get(index) {
        Some(b'Z') | Some(b'z') if index + 1 == bytes.len() => 0,
        Some(b'+') | Some(b'-') => {
            let sign = if bytes[index] == b'+' { 1_i64 } else { -1_i64 };
            if index + 6 != bytes.len() || bytes.get(index + 3) != Some(&b':') {
                return None;
            }
            let hours = parse_digits(bytes, index + 1, index + 3)? as i64;
            let minutes = parse_digits(bytes, index + 4, index + 6)? as i64;
            if hours > 23 || minutes > 59 {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?
        .checked_sub(offset_seconds)?;
    if seconds < 0 {
        return UNIX_EPOCH
            .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
            .and_then(|time| time.checked_add(Duration::from_nanos(u64::from(nanos))));
    }
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds as u64))
        .and_then(|time| time.checked_add(Duration::from_nanos(u64::from(nanos))))
}

fn parse_digits(bytes: &[u8], start: usize, end: usize) -> Option<u32> {
    let slice = bytes.get(start..end)?;
    slice.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month) || day < 1 || day > month_days[(month - 1) as usize] {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_index = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_records_are_classified_as_api_key() {
        let credential = parse_kiro_credential(
            br#"{"type":"kiro","api_key_env":"KIRO_TEST_KEY","region":"us-east-1"}"#,
        )
        .expect("JSON should parse")
        .expect("Kiro record should be handled");
        assert_eq!(credential.kind(), KiroCredentialKind::ApiKey);
        assert!(!credential.is_oauth());
        assert_eq!(credential.auth_method, KiroAuthMethod::ApiKey);
    }

    #[test]
    fn incomplete_oauth_record_is_rejected() {
        let result = parse_kiro_credential(
            br#"{"type":"kiro","auth_method":"idc","refresh_token":"r","client_id":"c"}"#,
        );
        assert!(matches!(
            result,
            Err(KiroCredentialError::MissingIdcClientCredentials)
        ));
    }

    #[test]
    fn profile_arn_region_takes_runtime_precedence() {
        let credential = KiroCredential {
            credential_type: KIRO_PLUGIN_IDENTIFIER.to_owned(),
            auth_method: KiroAuthMethod::Desktop,
            region: "us-east-1".to_owned(),
            profile_arn: "arn:aws:codewhisperer:eu-central-1:222222222222:profile/TEST".to_owned(),
            access_token: "access".to_owned(),
            ..KiroCredential::default()
        };
        assert_eq!(credential.runtime_region(), "eu-central-1");
    }

    #[test]
    fn expired_access_token_uses_minimum_refresh_interval() {
        let credential = KiroCredential {
            credential_type: KIRO_PLUGIN_IDENTIFIER.to_owned(),
            auth_method: KiroAuthMethod::Idc,
            access_token: "expired-access".into(),
            refresh_token: "old-refresh".into(),
            expired: "2020-01-01T00:00:00Z".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            ..KiroCredential::default()
        };
        assert_eq!(credential.refresh_interval(), Some(MIN_REFRESH_INTERVAL));
    }

    #[test]
    fn rotated_refresh_token_replaces_old_token_and_preserves_profile() {
        let mut credential = KiroCredential {
            credential_type: KIRO_PLUGIN_IDENTIFIER.to_owned(),
            auth_method: KiroAuthMethod::Idc,
            refresh_token: "old-refresh".into(),
            profile_arn: "arn:aws:codewhisperer:us-east-1:111111111111:profile/OLD".into(),
            ..KiroCredential::default()
        };
        credential
            .apply_oauth_tokens("new-access", "new-refresh", 3600, "")
            .expect("token response should be accepted");
        assert_eq!(credential.access_token, "new-access");
        assert_eq!(credential.refresh_token, "new-refresh");
        assert_eq!(
            credential.profile_arn,
            "arn:aws:codewhisperer:us-east-1:111111111111:profile/OLD"
        );
        assert!(credential
            .refresh_interval()
            .is_some_and(|interval| interval >= MIN_REFRESH_INTERVAL));
    }

    #[test]
    fn invalid_credentials_expose_clear_validation_errors() {
        let result = parse_kiro_credential(
            br#"{"type":"kiro","auth_method":"idc","access_token":"expired"}"#,
        );
        assert!(matches!(
            result,
            Err(KiroCredentialError::MissingIdcClientCredentials)
        ));

        let result = parse_kiro_credential(br#"{"type":"kiro","auth_method":"desktop"}"#);
        assert!(matches!(
            result,
            Err(KiroCredentialError::MissingOAuthTokens)
        ));
    }
}
