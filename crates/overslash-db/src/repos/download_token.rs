//! `download_tokens` — capability tokens for deferred byte delivery.
//!
//! Only `sha256(raw_token)` is stored; the raw value lives solely in the URL
//! handed back to the caller. See migration 107 for why the row holds a
//! *credential reference* rather than a resolved credential, and why redemption
//! is multi-use rather than single-use like [`super::magic_link_token`].

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DownloadTokenRow {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<String>,
    pub action_key: Option<String>,
    /// Replayable upstream request: `{method, url, headers, body}`. `None` on a
    /// result-backed token, which serves stored bytes instead of replaying.
    pub request: Option<serde_json::Value>,
    /// When set, redemption serves this stored result instead of dialing
    /// upstream. Mutually exclusive with `request` — see migration 111.
    pub call_result_id: Option<Uuid>,
    /// How to re-resolve the upstream credential at fetch time.
    pub credential_ref: serde_json::Value,
    pub mime: Option<String>,
    pub size_bytes: Option<i64>,
    pub filename: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub use_count: i32,
}

/// Fields that vary per mint. Grouped into a struct because the alternative is
/// a twelve-argument function where two adjacent `Option<String>`s
/// (`service_key`, `action_key`) and three more (`mime`, `filename`) are
/// trivially swappable at the call site with no type error to catch it.
pub struct NewDownloadToken<'a> {
    pub token_hash: &'a [u8],
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<&'a str>,
    pub action_key: Option<&'a str>,
    pub request: Option<serde_json::Value>,
    pub call_result_id: Option<Uuid>,
    pub credential_ref: serde_json::Value,
    pub mime: Option<&'a str>,
    pub size_bytes: Option<i64>,
    pub filename: Option<&'a str>,
    pub ttl_secs: i64,
    /// Upper bound on `expires_at`, on top of `ttl_secs`. Set when the token
    /// points at something with its own lifetime (a stored call result), so a
    /// capability cannot outlive the bytes it names.
    ///
    /// Applied in SQL rather than by the caller on purpose: `expires_at` is
    /// written from the database clock, so subtracting `now()` from it on the
    /// API side compares two clocks. Under skew that arithmetic yields a
    /// negative remaining lifetime, and any clamp of it mints a token that is
    /// dead on arrival while handing the caller a plausible `expires_at`.
    /// `LEAST` evaluates both bounds against the one clock that wrote them.
    pub expires_at_ceiling: Option<OffsetDateTime>,
}

/// Mint a token row. `expires_at = now() + ttl_secs`, further clamped by
/// `expires_at_ceiling` when one is given.
///
/// Postgres' `LEAST` ignores NULL operands rather than propagating them, so a
/// `None` ceiling leaves the plain TTL untouched — no second query shape.
/// A ceiling already in the past yields a row `claim` will never match, which
/// is the honest outcome: the bytes are gone, so the capability is too.
pub async fn create(
    pool: &PgPool,
    t: NewDownloadToken<'_>,
) -> Result<DownloadTokenRow, sqlx::Error> {
    sqlx::query_as!(
        DownloadTokenRow,
        "INSERT INTO download_tokens (
             token_hash, org_id, identity_id, service_instance_id,
             service_key, action_key, request, call_result_id, credential_ref,
             mime, size_bytes, filename, expires_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 LEAST(now() + make_interval(secs => $13), $14::timestamptz))
         RETURNING id, token_hash, org_id, identity_id, service_instance_id,
                   service_key, action_key, request, call_result_id, credential_ref,
                   mime, size_bytes, filename, created_at, expires_at,
                   last_used_at, use_count",
        t.token_hash,
        t.org_id,
        t.identity_id,
        t.service_instance_id,
        t.service_key,
        t.action_key,
        t.request,
        t.call_result_id,
        t.credential_ref,
        t.mime,
        t.size_bytes,
        t.filename,
        t.ttl_secs as f64,
        t.expires_at_ceiling,
    )
    .fetch_one(pool)
    .await
}

/// Claim a token for one fetch: bump the use counters iff the row exists and
/// hasn't expired. Returns `None` for unknown *or* expired, so the handler
/// can't accidentally distinguish the two and turn this into an oracle.
///
/// Unlike a single-use consume, this leaves the row redeemable until
/// `expires_at` — a resumed or retried download must be able to re-fetch. The
/// counters are bumped in the claiming statement so concurrent range requests
/// can't lose an increment.
pub async fn claim(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<DownloadTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        DownloadTokenRow,
        "UPDATE download_tokens
         SET use_count = use_count + 1, last_used_at = now()
         WHERE token_hash = $1 AND expires_at > now()
         RETURNING id, token_hash, org_id, identity_id, service_instance_id,
                   service_key, action_key, request, call_result_id, credential_ref,
                   mime, size_bytes, filename, created_at, expires_at,
                   last_used_at, use_count",
        token_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Drop expired rows. Best-effort housekeeping — an expired token is already
/// unusable via [`claim`], so this only reclaims space.
pub async fn prune_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!("DELETE FROM download_tokens WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}
