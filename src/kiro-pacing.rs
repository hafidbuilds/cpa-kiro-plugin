//! Per-credential request pacing and benching.
//!
//! CPA rotates credentials on its own, but concurrent requests on one Kiro
//! credential still trip Kiro's `USER_REQUEST_RATE_EXCEEDED`. With several
//! coding agents behind one gateway, bursts on the same account are the norm.
//! This module spaces requests per credential and remembers conditions Kiro
//! reports that outlive one request (monthly limit, suspension), so later
//! requests fail over without an upstream round trip. Credential selection,
//! failover, and the 429 backoff ladder stay with CPA. Behaviour follows
//! kiro4cpa-plugin's `ratelimit.go`.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use time::OffsetDateTime;

use crate::config::KiroPacingConfig;

/// Reason code on a refusal because the credential is still paced.
pub(crate) const REASON_PACED: &str = "KIRO_CREDENTIAL_PACED";
/// Reason code on a refusal because the account reported a monthly limit.
pub(crate) const REASON_BENCHED_MONTHLY: &str = "KIRO_CREDENTIAL_MONTHLY_LIMIT";
/// Reason code on a refusal because the account looks suspended.
pub(crate) const REASON_BENCHED_SUSPENDED: &str = "KIRO_CREDENTIAL_SUSPENDED";

/// Kiro's 403 body for an account it has blocked; the refresh token still works.
pub(crate) const BLOCKED_ACCOUNT_MESSAGE: &str = "User is not authorized to make this call";
const MONTHLY_REQUEST_COUNT: &str = "MONTHLY_REQUEST_COUNT";
const JITTER_FRACTION: f64 = 0.3;

/// Why a request was refused before reaching Kiro.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KiroAdmissionRefusal {
    pub(crate) status: i64,
    pub(crate) reason: &'static str,
    pub(crate) message: String,
    pub(crate) retry_after: Duration,
    pub(crate) credential_scoped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum BenchKind {
    MonthlyLimit,
    Suspended,
}

#[derive(Default)]
struct CredentialState {
    next_slot: Option<Instant>,
    benched: Option<(Instant, BenchKind)>,
}

/// Pacing state for all credentials. Time and jitter are passed in so the
/// policy can be tested without sleeping.
#[derive(Default)]
struct KiroPacer {
    states: HashMap<String, CredentialState>,
}

impl KiroPacer {
    /// Returns how long to wait before sending, or a refusal.
    fn admit(
        &mut self,
        auth_id: &str,
        pacing: KiroPacingConfig,
        now: Instant,
        jitter: f64,
    ) -> Result<Duration, KiroAdmissionRefusal> {
        let state = self.states.entry(auth_id.to_owned()).or_default();
        if let Some((until, kind)) = state.benched {
            if now < until {
                return Err(bench_refusal(kind, until - now));
            }
            state.benched = None;
        }
        let slot = state.next_slot.filter(|slot| *slot > now).unwrap_or(now);
        let wait = slot - now;
        if wait > pacing.max_interval {
            return Err(KiroAdmissionRefusal {
                status: 429,
                reason: REASON_PACED,
                message: format!(
                    "Kiro credential is paced for another {} ms; failing over",
                    wait.as_millis()
                ),
                retry_after: wait,
                credential_scoped: false,
            });
        }
        state.next_slot = Some(slot + paced_interval(pacing, jitter));
        Ok(wait)
    }

    fn bench(&mut self, auth_id: &str, kind: BenchKind, until: Instant) {
        self.states.entry(auth_id.to_owned()).or_default().benched = Some((until, kind));
    }
}

/// Draws the gap between two requests of one credential: uniform between the
/// configured bounds, then ±30% jitter so parallel gateways do not fire
/// together, capped at the maximum (the same cap the queue is refused at).
fn paced_interval(pacing: KiroPacingConfig, jitter: f64) -> Duration {
    let spread = pacing.max_interval.saturating_sub(pacing.min_interval);
    let base = pacing.min_interval.as_secs_f64() + spread.as_secs_f64() * jitter;
    let skew = base * JITTER_FRACTION * (jitter * 2.0 - 1.0);
    Duration::from_secs_f64((base + skew).max(0.0)).min(pacing.max_interval)
}

fn bench_refusal(kind: BenchKind, remaining: Duration) -> KiroAdmissionRefusal {
    let (status, reason, why, credential_scoped) = match kind {
        BenchKind::MonthlyLimit => (429, REASON_BENCHED_MONTHLY, "monthly limit reached", true),
        BenchKind::Suspended => (403, REASON_BENCHED_SUSPENDED, "account suspended", false),
    };
    KiroAdmissionRefusal {
        status,
        reason,
        message: format!(
            "Kiro credential is out of rotation for another {}s ({why})",
            remaining.as_secs()
        ),
        retry_after: remaining,
        credential_scoped,
    }
}

/// Classifies an upstream failure that should bench the credential.
fn bench_kind_for(status: i64, reason: &str, body: &str) -> Option<BenchKind> {
    if status == 402 || reason == MONTHLY_REQUEST_COUNT {
        return Some(BenchKind::MonthlyLimit);
    }
    if status == 403 && (body.contains("SUSPENDED") || body.contains(BLOCKED_ACCOUNT_MESSAGE)) {
        return Some(BenchKind::Suspended);
    }
    None
}

/// Time until the next UTC midnight: a monthly-limit credential is retried
/// daily, so added credits or an upgrade are noticed without a month's lockout.
pub(crate) fn until_next_utc_midnight(now: OffsetDateTime) -> Duration {
    let tomorrow = now.date().next_day().unwrap_or(now.date());
    let midnight = tomorrow.midnight().assume_utc();
    let remaining = midnight - now;
    Duration::from_secs(remaining.whole_seconds().max(1) as u64)
}

static KIRO_PACER: LazyLock<Mutex<KiroPacer>> = LazyLock::new(|| Mutex::new(KiroPacer::default()));

fn current_pacing() -> Option<KiroPacingConfig> {
    crate::config::loaded_kiro_config().pacing().ok()
}

fn jitter_sample() -> f64 {
    let mut bytes = [0_u8; 8];
    crate::dispatch::fill_random_bytes(&mut bytes);
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1_u64 << 53) as f64
}

/// Admits one upstream request for `auth_id`, sleeping until its slot.
///
/// Credentials without an auth ID, or with `disable_cooling`, are not paced.
pub(crate) fn admit_kiro_credential(
    auth_id: &str,
    disable_cooling: bool,
) -> Result<(), KiroAdmissionRefusal> {
    if auth_id.is_empty() || disable_cooling {
        return Ok(());
    }
    let Some(pacing) = current_pacing() else {
        return Ok(());
    };
    let wait = {
        let Ok(mut pacer) = KIRO_PACER.lock() else {
            return Ok(());
        };
        pacer.admit(auth_id, pacing, Instant::now(), jitter_sample())?
    };
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
    Ok(())
}

/// Benches a credential after a monthly-limit or suspension response.
pub(crate) fn record_kiro_upstream_failure(
    auth_id: &str,
    disable_cooling: bool,
    status: i64,
    reason: &str,
    body: &str,
) {
    if auth_id.is_empty() || disable_cooling {
        return;
    }
    let Some(kind) = bench_kind_for(status, reason, body) else {
        return;
    };
    let Some(pacing) = current_pacing() else {
        return;
    };
    let duration = match kind {
        BenchKind::MonthlyLimit => until_next_utc_midnight(OffsetDateTime::now_utc()),
        BenchKind::Suspended => pacing.suspend_cooldown,
    };
    if let Ok(mut pacer) = KIRO_PACER.lock() {
        pacer.bench(auth_id, kind, Instant::now() + duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pacing() -> KiroPacingConfig {
        KiroPacingConfig {
            min_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(2),
            suspend_cooldown: Duration::from_secs(3600),
        }
    }

    #[test]
    fn first_request_is_immediate_and_burst_queues_then_fails_over() {
        let mut pacer = KiroPacer::default();
        let now = Instant::now();
        assert_eq!(pacer.admit("a", pacing(), now, 0.5), Ok(Duration::ZERO));
        let second = pacer.admit("a", pacing(), now, 0.5).expect("queued");
        assert!(second >= Duration::from_millis(700) && second <= Duration::from_secs(2));
        // Queue keeps growing for a burst until the wait exceeds the max interval.
        let mut refused = None;
        for _ in 0..5 {
            if let Err(refusal) = pacer.admit("a", pacing(), now, 0.5) {
                refused = Some(refusal);
                break;
            }
        }
        let refusal = refused.expect("burst is eventually refused");
        assert_eq!(refusal.status, 429);
        assert_eq!(refusal.reason, REASON_PACED);
        assert!(!refusal.credential_scoped);
    }

    #[test]
    fn credentials_are_paced_independently() {
        let mut pacer = KiroPacer::default();
        let now = Instant::now();
        assert_eq!(pacer.admit("a", pacing(), now, 0.5), Ok(Duration::ZERO));
        assert_eq!(pacer.admit("b", pacing(), now, 0.5), Ok(Duration::ZERO));
    }

    #[test]
    fn interval_stays_within_bounds_for_any_jitter() {
        for jitter in [0.0, 0.25, 0.5, 0.75, 0.999_999] {
            let gap = paced_interval(pacing(), jitter);
            assert!(gap >= Duration::from_millis(700), "{gap:?}");
            assert!(gap <= Duration::from_secs(2), "{gap:?}");
        }
    }

    #[test]
    fn benched_credential_is_refused_until_the_bench_ends() {
        let mut pacer = KiroPacer::default();
        let now = Instant::now();
        pacer.bench("a", BenchKind::Suspended, now + Duration::from_secs(60));
        let refusal = pacer.admit("a", pacing(), now, 0.5).expect_err("benched");
        assert_eq!(refusal.status, 403);
        assert_eq!(refusal.reason, REASON_BENCHED_SUSPENDED);
        assert!(pacer
            .admit("a", pacing(), now + Duration::from_secs(61), 0.5)
            .is_ok());

        pacer.bench("b", BenchKind::MonthlyLimit, now + Duration::from_secs(60));
        let refusal = pacer.admit("b", pacing(), now, 0.5).expect_err("benched");
        assert_eq!(refusal.status, 429);
        assert!(refusal.credential_scoped);
    }

    #[test]
    fn only_monthly_limit_and_suspension_bench() {
        assert_eq!(
            bench_kind_for(429, MONTHLY_REQUEST_COUNT, ""),
            Some(BenchKind::MonthlyLimit)
        );
        assert_eq!(bench_kind_for(402, "", ""), Some(BenchKind::MonthlyLimit));
        assert_eq!(
            bench_kind_for(
                403,
                "",
                r#"{"message":"User is not authorized to make this call"}"#
            ),
            Some(BenchKind::Suspended)
        );
        assert_eq!(
            bench_kind_for(403, "", r#"{"reason":"ACCOUNT_SUSPENDED"}"#),
            Some(BenchKind::Suspended)
        );
        assert_eq!(bench_kind_for(429, "USER_REQUEST_RATE_EXCEEDED", ""), None);
        assert_eq!(
            bench_kind_for(
                403,
                "",
                "The bearer token included in the request is invalid"
            ),
            None
        );
    }

    #[test]
    fn monthly_bench_lasts_until_next_utc_midnight() {
        let now = time::Date::from_calendar_date(2026, time::Month::November, 12)
            .expect("date")
            .with_hms(23, 0, 0)
            .expect("time")
            .assume_utc();
        assert_eq!(until_next_utc_midnight(now), Duration::from_secs(3600));
    }
}
