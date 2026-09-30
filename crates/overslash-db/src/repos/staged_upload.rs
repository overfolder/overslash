//! `staged_uploads` — bytes the gateway holds briefly so an HTTP action can
//! carry them inline. See migration 132.
//!
//! The lifecycle is three states on one row: a mint writes `pending` with the
//! declared size already counted against quota, the single-use claim moves it
//! to `uploading`, and a verified push moves it to `ready`. A push that fails
//! deletes the row rather than re-arming it, for the upload_tokens reason: a
//! caller who can make the push fail must not be able to re-offer different
//! bytes against the same mint.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// A row's descriptor — everything except the bytes.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StagedUploadMeta {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub owner_user_id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// What a claim hands the redemption: the fixed-at-mint half of the row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedUpload {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub declared_size_bytes: i64,
    pub declared_sha256: Option<String>,
}

/// The ceilings a mint is checked against. `0` in any field means "no limit"
/// is *not* supported: every one of these exists to bound abuse, and a
/// deployment that wants them off turns the feature off instead.
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    pub identity_bytes: i64,
    pub identity_count: i64,
    pub org_bytes: i64,
}

/// Live usage, counted the way the quota is: bytes are the measured size once
/// known and the declared reservation until then.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    pub identity_bytes: i64,
    pub identity_count: i64,
    pub org_bytes: i64,
}

pub struct NewStagedUpload<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub owner_user_id: Uuid,
    pub token_hash: &'a [u8],
    pub filename: &'a str,
    pub content_type: &'a str,
    pub declared_size_bytes: i64,
    pub declared_sha256: Option<&'a str>,
    pub token_ttl_secs: i64,
}

#[derive(Debug)]
pub enum MintOutcome {
    Minted {
        id: Uuid,
        expires_at: OffsetDateTime,
        /// Rows removed to make room, oldest first. Empty unless `force`.
        evicted: Vec<Uuid>,
    },
    /// Refused. `usage` is what stood at the time, `evictable_bytes` what a
    /// `force` retry could free — zero when forcing would not help either.
    QuotaExceeded {
        usage: Usage,
        evictable_bytes: i64,
        evictable_count: i64,
    },
}

/// Reserve a slot for one upload, evicting the caller's own oldest uploads
/// first when `force` is set and that is what it takes.
///
/// One transaction under a per-org advisory lock, so two concurrent mints
/// cannot both read "under quota" and both insert. Eviction is all or nothing:
/// if everything the caller may evict still does not make room, nothing is
/// deleted and the refusal stands.
///
/// Only the caller's *own* rows are candidates. Evicting another identity's
/// upload to make room would let one agent delete a colleague's attachment
/// out from under a send it is about to make. Rows mid-push (`uploading`) and
/// rows pinned by a pending approval are never candidates either.
pub async fn mint(
    pool: &PgPool,
    n: NewStagedUpload<'_>,
    quota: Quota,
    force: bool,
) -> Result<MintOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query!(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        format!("staged_uploads:{}", n.org_id),
    )
    .execute(&mut *tx)
    .await?;

    let usage = usage_in(&mut tx, n.org_id, n.identity_id).await?;
    let need = n.declared_size_bytes;
    let over_bytes = |u: &Usage| {
        (u.identity_bytes + need - quota.identity_bytes)
            .max(u.org_bytes + need - quota.org_bytes)
            .max(0)
    };
    let over_count = |u: &Usage| (u.identity_count + 1 - quota.identity_count).max(0);

    let mut evicted = Vec::new();
    if over_bytes(&usage) > 0 || over_count(&usage) > 0 {
        let candidates = sqlx::query!(
            r#"SELECT id, COALESCE(size_bytes, declared_size_bytes) AS "bytes!"
               FROM staged_uploads
               WHERE identity_id = $1
                 AND status <> 'uploading'
                 AND expires_at > now()
                 AND (pinned_until IS NULL OR pinned_until <= now())
               ORDER BY created_at ASC, id ASC"#,
            n.identity_id,
        )
        .fetch_all(&mut *tx)
        .await?;
        let evictable_bytes: i64 = candidates.iter().map(|c| c.bytes).sum();
        let evictable_count = candidates.len() as i64;

        // Only live rows are candidates: an expired row the sweeper has not
        // reached yet is not in `usage`, so counting it as freed would let the
        // new mint land over quota.
        //
        // Take the oldest until both the byte and the count overage are
        // covered. Freed bytes count against both quotas, since an identity's
        // rows are also the org's.
        let (mut freed_bytes, mut freed_count) = (0i64, 0i64);
        for c in &candidates {
            if freed_bytes >= over_bytes(&usage) && freed_count >= over_count(&usage) {
                break;
            }
            evicted.push(c.id);
            freed_bytes += c.bytes;
            freed_count += 1;
        }
        let fits = freed_bytes >= over_bytes(&usage) && freed_count >= over_count(&usage);
        if !force || !fits {
            tx.rollback().await?;
            return Ok(MintOutcome::QuotaExceeded {
                usage,
                evictable_bytes: if fits { evictable_bytes } else { 0 },
                evictable_count: if fits { evictable_count } else { 0 },
            });
        }
        sqlx::query!(
            "DELETE FROM staged_uploads WHERE id = ANY($1) AND identity_id = $2",
            &evicted,
            n.identity_id,
        )
        .execute(&mut *tx)
        .await?;
    }

    let row = sqlx::query!(
        "INSERT INTO staged_uploads (
             org_id, identity_id, owner_user_id, token_hash, filename, content_type,
             declared_size_bytes, declared_sha256, expires_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))
         RETURNING id, expires_at",
        n.org_id,
        n.identity_id,
        n.owner_user_id,
        n.token_hash,
        n.filename,
        n.content_type,
        n.declared_size_bytes,
        n.declared_sha256,
        n.token_ttl_secs as f64,
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(MintOutcome::Minted {
        id: row.id,
        expires_at: row.expires_at,
        evicted,
    })
}

/// Live usage for one identity and its org. A row is live while it is unexpired
/// or pinned — the same predicate the sweeper negates.
async fn usage_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Usage, sqlx::Error> {
    let r = sqlx::query!(
        r#"SELECT
             COALESCE(SUM(COALESCE(size_bytes, declared_size_bytes))
                      FILTER (WHERE identity_id = $2), 0)::BIGINT AS "identity_bytes!",
             COUNT(*) FILTER (WHERE identity_id = $2) AS "identity_count!",
             COALESCE(SUM(COALESCE(size_bytes, declared_size_bytes)), 0)::BIGINT AS "org_bytes!"
           FROM staged_uploads
           WHERE org_id = $1
             AND (expires_at > now() OR pinned_until > now())"#,
        org_id,
        identity_id,
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(Usage {
        identity_bytes: r.identity_bytes,
        identity_count: r.identity_count,
        org_bytes: r.org_bytes,
    })
}

/// Take the token for its one push. Unknown, expired and already-claimed all
/// return `None`, so the handler cannot tell them apart. Clearing `token_hash`
/// in the same statement is what makes the token single-use.
pub async fn claim(pool: &PgPool, token_hash: &[u8]) -> Result<Option<ClaimedUpload>, sqlx::Error> {
    sqlx::query_as!(
        ClaimedUpload,
        "UPDATE staged_uploads
         SET status = 'uploading', token_hash = NULL
         WHERE token_hash = $1 AND status = 'pending' AND expires_at > now()
         RETURNING id, org_id, identity_id, filename, content_type,
                   declared_size_bytes, declared_sha256",
        token_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Store the verified bytes and start the staged TTL.
pub async fn complete(
    pool: &PgPool,
    id: Uuid,
    size_bytes: i64,
    sha256: &str,
    body_ciphertext: &[u8],
    ttl_secs: i64,
) -> Result<Option<OffsetDateTime>, sqlx::Error> {
    sqlx::query_scalar!(
        "UPDATE staged_uploads
         SET status = 'ready', size_bytes = $2, sha256 = $3, body_ciphertext = $4,
             redeemed_at = now(), expires_at = now() + make_interval(secs => $5)
         WHERE id = $1 AND status = 'uploading'
         RETURNING expires_at",
        id,
        size_bytes,
        sha256,
        body_ciphertext,
        ttl_secs as f64,
    )
    .fetch_optional(pool)
    .await
}

/// Drop a claimed row whose push did not land. Frees its reservation at once.
pub async fn abandon(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM staged_uploads WHERE id = $1 AND status = 'uploading'",
        id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Descriptors of the referenceable uploads among `ids`, in this org. Absent
/// ids are simply missing from the result; the caller decides what that means.
pub async fn find_ready(
    pool: &PgPool,
    org_id: Uuid,
    ids: &[Uuid],
) -> Result<Vec<StagedUploadMeta>, sqlx::Error> {
    sqlx::query_as!(
        StagedUploadMeta,
        "SELECT id, org_id, identity_id, owner_user_id, filename, content_type,
                size_bytes, sha256, expires_at
         FROM staged_uploads
         WHERE org_id = $1 AND id = ANY($2) AND status = 'ready'
           AND (expires_at > now() OR pinned_until > now())",
        org_id,
        ids,
    )
    .fetch_all(pool)
    .await
}

/// The bytes of one referenceable upload, still encrypted, with the digest they
/// were stored under.
pub async fn load_ciphertext(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<(String, Vec<u8>)>, sqlx::Error> {
    let r = sqlx::query!(
        r#"SELECT sha256 AS "sha256!", body_ciphertext AS "body_ciphertext!"
           FROM staged_uploads
           WHERE org_id = $1 AND id = $2 AND status = 'ready'
             AND (expires_at > now() OR pinned_until > now())"#,
        org_id,
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(r.map(|r| (r.sha256, r.body_ciphertext)))
}

/// Keep `ids` alive and unevictable until at least `until`. Only ever extends a
/// pin: two approvals naming one upload keep it for the later of the two.
pub async fn pin(
    pool: &PgPool,
    org_id: Uuid,
    ids: &[Uuid],
    until: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE staged_uploads
         SET pinned_until = GREATEST(COALESCE(pinned_until, $3), $3)
         WHERE org_id = $1 AND id = ANY($2)",
        org_id,
        ids,
        until,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Reclaim expired, unpinned rows — bytes and reservations alike.
pub async fn prune_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "DELETE FROM staged_uploads
         WHERE expires_at < now() AND (pinned_until IS NULL OR pinned_until < now())"
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}
