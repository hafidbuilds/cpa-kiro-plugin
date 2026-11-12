//! Writing credentials back through CPA, and coordinating token refreshes.
//!
//! Kiro rotates refresh tokens. If two requests (or a request and CPA's
//! scheduled `auth.refresh`) refresh the same account at once, the second
//! spends a refresh token the first already retired and the account is
//! logged out. Refreshes are therefore serialized per account, and the token
//! pairs they replace are remembered so a request holding an old snapshot
//! reuses the new tokens instead of refreshing again.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::abi::invoke_host_json;
use crate::kiro_credentials::KiroCredential;

/// Retired token pairs remembered per account (fingerprints only, no secrets).
const RETIRED_TOKEN_HISTORY: usize = 64;

/// Note written to a credential Kiro rejects as blocked. The management panel
/// shows it; the account is re-enabled by hand once the block is lifted.
pub(crate) const BLOCKED_ACCOUNT_NOTE: &str = "Kiro rejected this account (HTTP 403 User is not authorized to make this call); it may be blocked. Re-enable it after confirming the block is lifted.";

type TokenKey = [u8; 32];

#[derive(Default)]
struct RefreshRecord {
    retired: Vec<TokenKey>,
    latest: Option<KiroCredential>,
}

static REFRESH_RECORDS: LazyLock<Mutex<HashMap<String, Arc<Mutex<RefreshRecord>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn token_key(credential: &KiroCredential) -> TokenKey {
    Sha256::digest(format!("{}\0{}", credential.access_token, credential.refresh_token).as_bytes())
        .into()
}

fn record_for(auth_id: &str) -> Option<Arc<Mutex<RefreshRecord>>> {
    let mut records = REFRESH_RECORDS.lock().ok()?;
    Some(Arc::clone(records.entry(auth_id.to_owned()).or_default()))
}

/// Copies the token fields of `latest` onto `credential`, keeping the
/// caller's own account settings.
fn adopt_tokens(mut credential: KiroCredential, latest: &KiroCredential) -> KiroCredential {
    credential.access_token = latest.access_token.clone();
    credential.refresh_token = latest.refresh_token.clone();
    credential.expired = latest.expired.clone();
    if !latest.profile_arn.is_empty() {
        credential.profile_arn = latest.profile_arn.clone();
    }
    credential
}

/// Swaps a stale snapshot for the tokens a previous refresh produced.
///
/// CPA can hand the executor an auth record from before a refresh this plugin
/// already did; sending its retired tokens would fail or, worse, spend a
/// rotated refresh token later.
pub(crate) fn current_kiro_credential(auth_id: &str, credential: KiroCredential) -> KiroCredential {
    if auth_id.is_empty() || !credential.is_oauth() {
        return credential;
    }
    let Some(record) = record_for(auth_id) else {
        return credential;
    };
    let Ok(record) = record.lock() else {
        return credential;
    };
    match &record.latest {
        Some(latest) if record.retired.contains(&token_key(&credential)) => {
            adopt_tokens(credential, latest)
        }
        _ => credential,
    }
}

/// Refreshes `credential` at most once per token pair.
///
/// Callers holding the same (or an already retired) token pair wait for the
/// refresh in progress and reuse its result while that access token is valid.
pub(crate) fn refresh_kiro_credential_once<E>(
    auth_id: &str,
    credential: KiroCredential,
    refresh: impl FnOnce(KiroCredential) -> Result<KiroCredential, E>,
) -> Result<KiroCredential, E> {
    if auth_id.is_empty() || !credential.is_oauth() {
        return refresh(credential);
    }
    let Some(record) = record_for(auth_id) else {
        return refresh(credential);
    };
    let Ok(mut record) = record.lock() else {
        return refresh(credential);
    };
    let key = token_key(&credential);
    if let Some(latest) = &record.latest {
        if record.retired.contains(&key) && !latest.access_token_expired() {
            return Ok(adopt_tokens(credential, latest));
        }
    }
    let fresh = refresh(credential)?;
    if !record.retired.contains(&key) {
        record.retired.push(key);
        if record.retired.len() > RETIRED_TOKEN_HISTORY {
            record.retired.remove(0);
        }
    }
    record.latest = Some(fresh.clone());
    Ok(fresh)
}

/// Auth file name CPA stores this credential under.
pub(crate) fn kiro_auth_file_name(auth_id: &str, auth_path: &str) -> Option<String> {
    let base = |value: &str| {
        value
            .rsplit(['/', '\\'])
            .next()
            .map(str::trim)
            .filter(|name| !name.is_empty() && *name != "." && name.ends_with(".json"))
            .map(str::to_owned)
    };
    base(auth_path).or_else(|| base(auth_id))
}

/// Overlays the credential's fields onto the original auth-file JSON, so
/// fields this plugin does not model survive the write.
pub(crate) fn merge_kiro_storage(original: &[u8], credential: &KiroCredential) -> Value {
    let mut merged: Map<String, Value> = serde_json::from_slice(original).unwrap_or_default();
    if let Ok(Value::Object(fields)) = serde_json::to_value(credential) {
        for (key, value) in fields {
            merged.insert(key, value);
        }
    }
    // `disabled` is never serialized when false, so a disable made in CPA after
    // this snapshot was taken survives; the plugin only ever adds it.
    Value::Object(merged)
}

/// Writes a credential back to its CPA auth file through `host.auth.save`.
pub(crate) fn persist_kiro_credential(
    auth_id: &str,
    auth_path: &str,
    original_storage: &[u8],
    credential: &KiroCredential,
) -> Result<(), String> {
    let name = kiro_auth_file_name(auth_id, auth_path)
        .ok_or_else(|| "cannot persist Kiro credential without an auth file name".to_string())?;
    let request = json!({"name": name, "json": merge_kiro_storage(original_storage, credential)});
    let payload = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    invoke_host_json("host.auth.save", &payload).map(|_| ())
}

/// Marks a credential Kiro reports as blocked: disabled, timestamped, and noted.
/// A note the user wrote is kept. Returns `false` when it was already marked.
pub(crate) fn mark_kiro_account_blocked(credential: &mut KiroCredential, now: &str) -> bool {
    if credential.disabled && !credential.blocked_at.is_empty() {
        return false;
    }
    credential.disabled = true;
    credential.blocked_at = now.to_owned();
    if credential.note.is_empty() {
        credential.note = BLOCKED_ACCOUNT_NOTE.to_owned();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiro_credentials::KiroAuthMethod;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn credential(access: &str, refresh: &str) -> KiroCredential {
        KiroCredential {
            credential_type: "kiro".into(),
            auth_method: KiroAuthMethod::Desktop,
            access_token: access.into(),
            refresh_token: refresh.into(),
            expired: "2999-01-01T00:00:00Z".into(),
            ..KiroCredential::default()
        }
    }

    #[test]
    fn concurrent_stale_snapshots_refresh_once_and_share_the_result() {
        let calls = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let calls = Arc::clone(&calls);
                std::thread::spawn(move || {
                    refresh_kiro_credential_once::<()>(
                        "auth-shared",
                        credential("old", "r1"),
                        |_| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            Ok(credential("new", "r2"))
                        },
                    )
                    .expect("refresh")
                })
            })
            .collect();
        for thread in threads {
            let fresh = thread.join().expect("thread");
            assert_eq!(fresh.access_token, "new");
            assert_eq!(fresh.refresh_token, "r2");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the rotated refresh token was spent twice"
        );
        let swapped = current_kiro_credential("auth-shared", credential("old", "r1"));
        assert_eq!(swapped.refresh_token, "r2");
    }

    #[test]
    fn current_tokens_refresh_again_when_rejected() {
        let first =
            refresh_kiro_credential_once::<()>("auth-again", credential("a1", "r1"), |_| {
                Ok(credential("a2", "r2"))
            })
            .expect("first refresh");
        let second =
            refresh_kiro_credential_once::<()>("auth-again", first, |_| Ok(credential("a3", "r3")))
                .expect("second refresh");
        assert_eq!(second.access_token, "a3");
    }

    #[test]
    fn auth_file_name_prefers_path_and_requires_json() {
        assert_eq!(
            kiro_auth_file_name("ignored", "/auth/kiro-desktop-a@b.com.json").as_deref(),
            Some("kiro-desktop-a@b.com.json")
        );
        assert_eq!(
            kiro_auth_file_name("kiro-x.json", "").as_deref(),
            Some("kiro-x.json")
        );
        assert_eq!(kiro_auth_file_name("kiro-x", ""), None);
    }

    #[test]
    fn merge_keeps_unknown_fields_and_never_re_enables_an_account() {
        let original =
            br#"{"type":"kiro","custom_field":"kept","disabled":true,"access_token":"old"}"#;
        let merged = merge_kiro_storage(original, &credential("new", "r"));
        assert_eq!(merged["custom_field"], "kept");
        assert_eq!(merged["access_token"], "new");
        assert_eq!(merged["disabled"], true);
    }

    #[test]
    fn blocked_marking_keeps_user_note_and_happens_once() {
        let mut account = credential("a", "r");
        account.note = "team account".into();
        assert!(mark_kiro_account_blocked(
            &mut account,
            "2026-11-12T00:00:00Z"
        ));
        assert!(account.disabled);
        assert_eq!(account.note, "team account");
        assert!(!mark_kiro_account_blocked(
            &mut account,
            "2026-11-13T00:00:00Z"
        ));
        assert_eq!(account.blocked_at, "2026-11-12T00:00:00Z");
    }
}
