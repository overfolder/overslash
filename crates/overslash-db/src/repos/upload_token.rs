//! `upload_tokens` — single-use capability tokens for pushing bytes into a
//! service.
//!
//! The inbound mirror of [`super::download_token`], and deliberately not a
//! mirror of its *redemption* rule. A download token is multi-use so a dropped
//! transfer can resume; redeeming it twice re-fetches the same bytes. An upload
//! token redeemed twice would store two different payloads under one
//! authorization, so "what the reviewer approved" would stop having an answer.
//! [`claim`] therefore consumes.
//!
//! Only `sha256(raw_token)` is stored. See migration 116 for why a row holds a
//! credential *reference* rather than a credential, and why the declared and
//! stored halves are separate columns rather than one descriptor blob.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UploadTokenRow {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<String>,
    pub action_key: Option<String>,
    /// The upstream request to make once the bytes arrive: `{method, url,
    /// headers, body}`, with `body` always null — the bytes are not in the row.
    pub request: serde_json::Value,
    /// How to re-resolve the upstream credential at redemption time.
    pub credential_ref: serde_json::Value,
    /// What the caller said it would push. Fixed at mint, so this is what a
    /// reviewer actually approved.
    pub declared_sha256: Option<String>,
    pub declared_size_bytes: Option<i64>,
    pub declared_mime: Option<String>,
    pub declared_filename: Option<String>,
    pub max_bytes: i64,
    /// Which query parameter the byte route takes the filename in. `None`
    /// means it takes none.
    pub filename_param: Option<String>,
    /// The template's `result` jq block, resolved at mint. Redemption holds a
    /// token rather than an action key, so it cannot look the declaration back
    /// up — the spec has to travel with the capability.
    pub result_spec: Option<serde_json::Value>,
    /// What the upstream recorded. Written only by [`complete`].
    pub stored_media_path: Option<String>,
    pub stored_sha256: Option<String>,
    pub stored_size_bytes: Option<i64>,
    pub stored_mime: Option<String>,
    pub stored_filename: Option<String>,
    pub completed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

/// Fields that vary per mint. A struct for the same reason
/// [`super::download_token::NewDownloadToken`] is one: the four adjacent
/// `Option<&str>` declarations are trivially swappable at a call site with no
/// type error to catch it.
pub struct NewUploadToken<'a> {
    pub token_hash: &'a [u8],
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<&'a str>,
    pub action_key: Option<&'a str>,
    pub request: serde_json::Value,
    pub credential_ref: serde_json::Value,
    pub declared_sha256: Option<&'a str>,
    pub declared_size_bytes: Option<i64>,
    pub declared_mime: Option<&'a str>,
    pub declared_filename: Option<&'a str>,
    pub max_bytes: i64,
    pub filename_param: Option<&'a str>,
    pub result_spec: Option<serde_json::Value>,
    pub ttl_secs: i64,
}

/// What the upstream said it stored, for [`complete`].
pub struct StoredDescriptor<'a> {
    pub media_path: &'a str,
    pub sha256: Option<&'a str>,
    pub size_bytes: Option<i64>,
    pub mime: Option<&'a str>,
    pub filename: Option<&'a str>,
}

/// Mint a token row. `expires_at = now() + ttl_secs`, from the database clock.
pub async fn create(pool: &PgPool, t: NewUploadToken<'_>) -> Result<UploadTokenRow, sqlx::Error> {
    sqlx::query_as!(
        UploadTokenRow,
        "INSERT INTO upload_tokens (
             token_hash, org_id, identity_id, service_instance_id,
             service_key, action_key, request, credential_ref,
             declared_sha256, declared_size_bytes, declared_mime, declared_filename,
             max_bytes, filename_param, result_spec, expires_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                 now() + make_interval(secs => $16))
         RETURNING id, token_hash, org_id, identity_id, service_instance_id,
                   service_key, action_key, request, credential_ref,
                   declared_sha256, declared_size_bytes, declared_mime, declared_filename,
                   max_bytes, filename_param, result_spec, stored_media_path, stored_sha256,
                   stored_size_bytes,
                   stored_mime, stored_filename, completed_at,
                   created_at, expires_at, consumed_at",
        t.token_hash,
        t.org_id,
        t.identity_id,
        t.service_instance_id,
        t.service_key,
        t.action_key,
        t.request,
        t.credential_ref,
        t.declared_sha256,
        t.declared_size_bytes,
        t.declared_mime,
        t.declared_filename,
        t.max_bytes,
        t.filename_param,
        t.result_spec,
        t.ttl_secs as f64,
    )
    .fetch_one(pool)
    .await
}

/// Consume a token for one push: mark it used iff it exists, hasn't expired,
/// and hasn't already been claimed.
///
/// Unknown, expired and already-consumed all return `None`, so the handler
/// cannot accidentally distinguish them and turn this into an oracle. The
/// guard is in the UPDATE rather than a read-then-write so two concurrent
/// redemptions cannot both win — the loser sees `None` and 404s, which is the
/// correct answer for a token whose one push already went somewhere.
///
/// Claiming is what *starts* the push, not what completes it: a redemption that
/// then fails upstream leaves a consumed row with no `completed_at`. That is
/// deliberate. Re-arming on failure would mean a caller who can make the
/// upstream fail can re-offer bytes indefinitely against one approval.
pub async fn claim(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<UploadTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        UploadTokenRow,
        "UPDATE upload_tokens
         SET consumed_at = now()
         WHERE token_hash = $1 AND expires_at > now() AND consumed_at IS NULL
         RETURNING id, token_hash, org_id, identity_id, service_instance_id,
                   service_key, action_key, request, credential_ref,
                   declared_sha256, declared_size_bytes, declared_mime, declared_filename,
                   max_bytes, filename_param, result_spec, stored_media_path, stored_sha256,
                   stored_size_bytes,
                   stored_mime, stored_filename, completed_at,
                   created_at, expires_at, consumed_at",
        token_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Record what the upstream stored. Only the first call lands; a second
/// returns `None`.
pub async fn complete(
    pool: &PgPool,
    id: Uuid,
    d: StoredDescriptor<'_>,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        "UPDATE upload_tokens
         SET completed_at = now(), stored_media_path = $2, stored_sha256 = $3,
             stored_size_bytes = $4, stored_mime = $5, stored_filename = $6
         WHERE id = $1 AND completed_at IS NULL
         RETURNING id",
        id,
        d.media_path,
        d.sha256,
        d.size_bytes,
        d.mime,
        d.filename,
    )
    .fetch_optional(pool)
    .await
}

/// Drop expired rows. Best-effort housekeeping — an expired token is already
/// unusable via [`claim`], so this only reclaims space.
pub async fn prune_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!("DELETE FROM upload_tokens WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}
