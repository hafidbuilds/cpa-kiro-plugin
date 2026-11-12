//! Kiro account usage: the account identity used to name auth files, and the
//! credit quota reported to CPA's management panel.

use serde_json::{json, Value};

use crate::dispatch::{host_http_get, profile_list_headers, query_escape, HostHttpError};
use crate::kiro_credentials::{api_region, candidate_management_regions, KiroCredential};

/// Calls `Get-Usage-Limits` on the Kiro management API, trying each management
/// region the credential may live in.
///
/// A 401 is returned at once so the caller can refresh the token; a 403 or a
/// profile complaint moves on to the next region.
pub(crate) fn fetch_kiro_usage_limits(
    callback_id: &str,
    credential: &KiroCredential,
    email_required: bool,
) -> Result<Value, HostHttpError> {
    let token = credential.bearer_token().map_err(|error| HostHttpError {
        status: 401,
        detail: error.to_string(),
    })?;
    let headers = profile_list_headers(&token, credential.auth_method);
    let mut last_error = HostHttpError {
        status: 0,
        detail: "no Kiro management region answered".into(),
    };
    for region in candidate_management_regions(api_region(&credential.region)) {
        let mut url = format!(
            "https://management.{region}.kiro.dev/Get-Usage-Limits?origin=KIRO_CLI&resourceType=CREDIT&isEmailRequired={email_required}"
        );
        if !credential.profile_arn.is_empty() {
            url.push_str("&profileArn=");
            url.push_str(&query_escape(&credential.profile_arn));
        }
        let response = match host_http_get(callback_id, &url, &headers) {
            Ok(response) => response,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        if response.status == 200 {
            return serde_json::from_slice(&response.body).map_err(|error| HostHttpError {
                status: 0,
                detail: format!("decode Kiro usage limits: {error}"),
            });
        }
        let detail = crate::dispatch::limited_error_body(&response.body);
        let error = HostHttpError {
            status: response.status,
            detail,
        };
        let try_next_region = response.status == 403
            || (response.status == 400
                && (error.detail.contains("Invalid profileArn")
                    || error.detail.contains("Improperly formed request")));
        if !try_next_region {
            return Err(error);
        }
        last_error = error;
    }
    Err(last_error)
}

/// Fills `email` and `user_id` from the usage API so repeated logins of one
/// account map to one auth file. Best effort: failures leave the credential as is.
pub(crate) fn resolve_kiro_account_identity(callback_id: &str, credential: &mut KiroCredential) {
    if !credential.is_oauth() || (!credential.email.is_empty() && !credential.user_id.is_empty()) {
        return;
    }
    let Ok(limits) = fetch_kiro_usage_limits(callback_id, credential, true) else {
        return;
    };
    apply_kiro_account_identity(credential, &limits);
}

fn apply_kiro_account_identity(credential: &mut KiroCredential, limits: &Value) {
    let user_info = limits.get("userInfo");
    let field = |name: &str| {
        user_info
            .and_then(|info| info.get(name))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    if credential.email.is_empty() {
        if let Some(email) = field("email") {
            credential.email = email;
        }
    }
    if credential.user_id.is_empty() {
        if let Some(user_id) = field("userId") {
            credential.user_id = user_id;
        }
    }
}

/// Kiro keeps used-up or expired free trials and bonuses in the response; like
/// kiro.rs and kiro4cpa, only ACTIVE ones add to the usable credit.
const QUOTA_ACTIVE: &str = "ACTIVE";

/// Maps `Get-Usage-Limits` to CPA's `QuotaFetchResponse`.
pub(crate) fn kiro_quota_response(limits: &Value) -> Option<Value> {
    let breakdown = limits.get("usageBreakdownList")?.as_array()?;
    if breakdown.is_empty() {
        return None;
    }
    let number = |value: Option<&Value>| value.and_then(Value::as_f64).unwrap_or(0.0);
    let text = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let mut summary = Vec::new();
    let mut groups = Vec::new();
    for item in breakdown {
        let name = text(item.get("displayName"))
            .or_else(|| text(item.get("resourceType")))
            .unwrap_or_else(|| "Credit".into());
        let key = text(item.get("resourceType"))
            .unwrap_or_else(|| "credit".into())
            .to_ascii_lowercase();
        let (base_used, base_limit) = (
            number(
                item.get("currentUsageWithPrecision")
                    .or_else(|| item.get("currentUsage")),
            ),
            number(
                item.get("usageLimitWithPrecision")
                    .or_else(|| item.get("usageLimit")),
            ),
        );
        let (mut used, mut limit) = (base_used, base_limit);
        let mut buckets = vec![quota_bucket(
            "monthly",
            "Monthly",
            base_used,
            base_limit,
            number(
                item.get("nextDateReset")
                    .or_else(|| limits.get("nextDateReset")),
            ),
        )];
        if let Some(trial) = item.get("freeTrialInfo").filter(|trial| trial.is_object()) {
            let trial_limit = number(trial.get("usageLimitWithPrecision"));
            if text(trial.get("freeTrialStatus")).as_deref() == Some(QUOTA_ACTIVE)
                && trial_limit > 0.0
            {
                let trial_used = number(trial.get("currentUsageWithPrecision"));
                used += trial_used;
                limit += trial_limit;
                buckets.push(quota_bucket(
                    "free_trial",
                    "Free trial",
                    trial_used,
                    trial_limit,
                    number(trial.get("freeTrialExpiry")),
                ));
            }
        }
        for bonus in item
            .get("bonuses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let bonus_limit = number(bonus.get("usageLimit"));
            if text(bonus.get("status")).as_deref() != Some(QUOTA_ACTIVE) || bonus_limit <= 0.0 {
                continue;
            }
            let bonus_used = number(bonus.get("currentUsage"));
            used += bonus_used;
            limit += bonus_limit;
            let label = text(bonus.get("displayName"))
                .map(|name| format!("Bonus ({name})"))
                .unwrap_or_else(|| "Bonus".into());
            buckets.push(quota_bucket(
                &text(bonus.get("displayName")).unwrap_or_else(|| "bonus".into()),
                &label,
                bonus_used,
                bonus_limit,
                number(bonus.get("expiresAt")),
            ));
        }
        summary.push(
            json!({"key": format!("{key}_used"), "label": "Used", "value": used, "unit": name}),
        );
        summary.push(
            json!({"key": format!("{key}_limit"), "label": "Limit", "value": limit, "unit": name}),
        );
        groups.push(json!({"displayName": name, "buckets": buckets}));
    }
    let mut response = json!({"summary": summary, "groups": groups});
    if let Some(plan) = limits
        .pointer("/subscriptionInfo/subscriptionTitle")
        .and_then(Value::as_str)
        .filter(|plan| !plan.trim().is_empty())
    {
        response["subscription"] = json!({"plan": plan.trim()});
    }
    Some(response)
}

fn quota_bucket(window: &str, label: &str, used: f64, limit: f64, reset_unix: f64) -> Value {
    let mut description = format!("{label} · {} / {}", trim_float(used), trim_float(limit));
    let mut remaining = 0.0;
    if limit > 0.0 {
        remaining = (1.0 - used / limit).clamp(0.0, 1.0);
        if used >= limit {
            description.push_str("; quota used up");
        }
    }
    let mut bucket =
        json!({"window": window, "remainingFraction": remaining, "description": description});
    if reset_unix > 0.0 {
        if let Ok(reset) = time::OffsetDateTime::from_unix_timestamp(reset_unix as i64) {
            bucket["resetTime"] = json!(crate::dispatch::format_rfc3339_utc(reset));
        }
    }
    bucket
}

fn trim_float(value: f64) -> String {
    let formatted = format!("{value:.2}");
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{apply_kiro_account_identity, kiro_quota_response};
    use crate::kiro_credentials::KiroCredential;
    use serde_json::json;

    #[test]
    fn account_identity_fills_missing_email_and_user_id_only() {
        let mut credential = KiroCredential {
            email: "kept@example.com".into(),
            ..KiroCredential::default()
        };
        apply_kiro_account_identity(
            &mut credential,
            &json!({"userInfo": {"email": "other@example.com", "userId": "user-1"}}),
        );
        assert_eq!(credential.email, "kept@example.com");
        assert_eq!(credential.user_id, "user-1");
    }

    #[test]
    fn quota_counts_only_active_trials_and_bonuses() {
        let limits = json!({
            "subscriptionInfo": {"subscriptionTitle": "KIRO STUDENT"},
            "nextDateReset": 1796083200.0,
            "usageBreakdownList": [{
                "resourceType": "CREDIT",
                "displayName": "Credit",
                "currentUsageWithPrecision": 10.5,
                "usageLimitWithPrecision": 1000.0,
                "freeTrialInfo": {"freeTrialStatus": "EXPIRED", "currentUsageWithPrecision": 50.0, "usageLimitWithPrecision": 500.0},
                "bonuses": [
                    {"displayName": "Welcome", "status": "ACTIVE", "currentUsage": 1.0, "usageLimit": 100.0, "expiresAt": 1796083200.0},
                    {"displayName": "Old", "status": "EXPIRED", "currentUsage": 5.0, "usageLimit": 5.0}
                ]
            }]
        });
        let response = kiro_quota_response(&limits).expect("quota response");
        assert_eq!(response["subscription"]["plan"], "KIRO STUDENT");
        assert_eq!(response["summary"][0]["key"], "credit_used");
        assert_eq!(response["summary"][0]["value"], 11.5);
        assert_eq!(response["summary"][1]["value"], 1100.0);
        let buckets = response["groups"][0]["buckets"]
            .as_array()
            .expect("buckets");
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0]["window"], "monthly");
        assert_eq!(buckets[0]["resetTime"], "2026-12-01T00:00:00Z");
        assert_eq!(buckets[1]["description"], "Bonus (Welcome) · 1 / 100");
    }

    #[test]
    fn quota_is_unavailable_without_usage_breakdown() {
        assert!(kiro_quota_response(&json!({"usageBreakdownList": []})).is_none());
    }
}
