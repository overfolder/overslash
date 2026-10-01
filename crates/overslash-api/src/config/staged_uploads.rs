//! Knobs for gateway-staged uploads (`x-overslash-staged-upload`).
//!
//! Nested for the reason [`super::AsyncExecutionConfig`] is: `Config` is built
//! as a struct literal in several test harnesses, so one field here costs one
//! line in each of them instead of seven.
//!
//! Every limit below is an abuse bound, not a tuning knob. Staged bytes live in
//! Postgres and cross this process twice (in on redemption, out base64-encoded
//! on send), so the ceilings are sized against memory and table growth under a
//! hostile caller, not against a friendly one.

use overslash_env as env;

/// A per-upload and per-send ceiling no deployment may raise past. Base64 grows
/// bytes by 4/3, so 20 MiB is ~27 MiB on the wire to the Mailbox Gateway —
/// already close to Cloud Run's 32 MiB request cap on the far side.
pub const HARD_MAX_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct StagedUploadConfig {
    /// `STAGED_UPLOADS_ENABLED`. Off refuses every mint; uploads already staged
    /// still send until they expire, so turning it off never breaks a pending
    /// approval.
    pub enabled: bool,
    /// `STAGED_UPLOAD_MAX_BYTES`, clamped to [`HARD_MAX_BYTES`]. Bounds one
    /// upload *and* the sum a single call may inline, matching overfwd's own
    /// `OVERFWD_MAX_ATTACHMENT_BYTES` default.
    pub max_bytes: u64,
    /// `STAGED_UPLOAD_TTL_SECS`. How long a redeemed upload stays sendable.
    /// Long enough to outlive an ordinary approval wait; a pending approval
    /// pins its uploads past this anyway.
    pub ttl_secs: i64,
    /// `STAGED_UPLOAD_IDENTITY_QUOTA_BYTES`. Live bytes (stored plus reserved)
    /// one identity may hold.
    pub identity_quota_bytes: i64,
    /// `STAGED_UPLOAD_IDENTITY_MAX_COUNT`. Live uploads one identity may hold,
    /// so a flood of tiny files is bounded as well as a few large ones.
    pub identity_max_count: i64,
    /// `STAGED_UPLOAD_ORG_QUOTA_BYTES`. Live bytes across the whole org — the
    /// bound on how much of the database one tenant can occupy.
    pub org_quota_bytes: i64,
    /// `STAGED_UPLOAD_CONCURRENCY`. Uploads one replica buffers at once, across
    /// redemptions and send-time inlining. Each holds up to `max_bytes`
    /// plaintext plus its ciphertext or base64, so this is the memory bound.
    pub concurrency: usize,
}

impl Default for StagedUploadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_bytes: 10 * 1024 * 1024,
            ttl_secs: 24 * 60 * 60,
            identity_quota_bytes: 50 * 1024 * 1024,
            identity_max_count: 50,
            org_quota_bytes: 200 * 1024 * 1024,
            concurrency: 4,
        }
    }
}

impl StagedUploadConfig {
    pub(super) fn from_env() -> Self {
        let d = Self::default();
        Self {
            enabled: env::flag_or("STAGED_UPLOADS_ENABLED", d.enabled),
            max_bytes: env::parse_opt("STAGED_UPLOAD_MAX_BYTES")
                .filter(|n: &u64| *n > 0)
                .unwrap_or(d.max_bytes)
                .min(HARD_MAX_BYTES),
            ttl_secs: env::parse_opt("STAGED_UPLOAD_TTL_SECS")
                .filter(|n: &i64| *n > 0)
                .unwrap_or(d.ttl_secs),
            identity_quota_bytes: env::parse_opt("STAGED_UPLOAD_IDENTITY_QUOTA_BYTES")
                .filter(|n: &i64| *n > 0)
                .unwrap_or(d.identity_quota_bytes),
            identity_max_count: env::parse_opt("STAGED_UPLOAD_IDENTITY_MAX_COUNT")
                .filter(|n: &i64| *n > 0)
                .unwrap_or(d.identity_max_count),
            org_quota_bytes: env::parse_opt("STAGED_UPLOAD_ORG_QUOTA_BYTES")
                .filter(|n: &i64| *n > 0)
                .unwrap_or(d.org_quota_bytes),
            concurrency: env::parse_opt("STAGED_UPLOAD_CONCURRENCY")
                .filter(|n: &usize| *n > 0)
                .unwrap_or(d.concurrency),
        }
    }
}
