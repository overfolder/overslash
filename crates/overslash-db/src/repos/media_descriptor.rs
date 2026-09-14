//! `media_descriptors` — what the gateway knows about bytes it has moved.
//!
//! Both halves of the media path deal in *references*: a content-addressed
//! path in, the same path back out. That keeps bytes out of an agent's context,
//! but it means an approval to send a file could only ever show a reviewer a
//! hash. This table is how the gateway answers "what is `/media/<64 hex>`?"
//! without a network round-trip and a credential use inside the approval path.
//!
//! Best-effort by construction. A reference the gateway never handled — bytes
//! pushed to the service out of band — is simply absent, and the disclosure
//! falls back to the raw path. That fallback is lossless: the reviewer still
//! sees exactly the string the call will send, so a miss is "no better than
//! before", never "misleading".

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MediaDescriptorRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<String>,
    pub media_path: String,
    pub sha256: Option<String>,
    pub mime: Option<String>,
    pub size_bytes: Option<i64>,
    pub filename: Option<String>,
    pub source: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
}

/// Where a descriptor was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaSource {
    /// Seen passing through a tool result on its way out.
    Download,
    /// Pushed through the gateway on its way in.
    Upload,
}

impl MediaSource {
    fn as_str(self) -> &'static str {
        match self {
            MediaSource::Download => "download",
            MediaSource::Upload => "upload",
        }
    }
}

pub struct NewMediaDescriptor<'a> {
    pub org_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<&'a str>,
    pub media_path: &'a str,
    pub sha256: Option<&'a str>,
    pub mime: Option<&'a str>,
    pub size_bytes: Option<i64>,
    pub filename: Option<&'a str>,
    pub source: MediaSource,
}

/// Record a descriptor, or refresh one already known.
///
/// `COALESCE(EXCLUDED.x, existing.x)` on every metadata column: a later
/// observation that knows less must not erase what an earlier one knew. The
/// motivating case is real — a tool result may carry mime and size while an
/// upload response carries only the path, and the reviewer wants both.
///
/// `source` is deliberately *not* coalesced but left at its original value:
/// provenance is about where these bytes entered the system, and that does not
/// change when they are seen again.
pub async fn record(pool: &PgPool, d: NewMediaDescriptor<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO media_descriptors (
             org_id, service_instance_id, service_key, media_path,
             sha256, mime, size_bytes, filename, source
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (org_id, service_instance_id, media_path) DO UPDATE
         SET sha256      = COALESCE(EXCLUDED.sha256, media_descriptors.sha256),
             mime        = COALESCE(EXCLUDED.mime, media_descriptors.mime),
             size_bytes  = COALESCE(EXCLUDED.size_bytes, media_descriptors.size_bytes),
             filename    = COALESCE(EXCLUDED.filename, media_descriptors.filename),
             service_key = COALESCE(EXCLUDED.service_key, media_descriptors.service_key),
             last_seen_at = now()",
        d.org_id,
        d.service_instance_id,
        d.service_key,
        d.media_path,
        d.sha256,
        d.mime,
        d.size_bytes,
        d.filename,
        d.source.as_str(),
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up one reference, scoped to the org and the instance that stores it.
///
/// A content address is only meaningful on the host holding the bytes, so the
/// same hash on two instances is the same bytes but not the same stored object
/// — hence the instance in the key rather than the org alone.
pub async fn find(
    pool: &PgPool,
    org_id: Uuid,
    service_instance_id: Option<Uuid>,
    media_path: &str,
) -> Result<Option<MediaDescriptorRow>, sqlx::Error> {
    sqlx::query_as!(
        MediaDescriptorRow,
        "SELECT id, org_id, service_instance_id, service_key, media_path,
                sha256, mime, size_bytes, filename, source, first_seen_at, last_seen_at
           FROM media_descriptors
          WHERE org_id = $1
            AND service_instance_id IS NOT DISTINCT FROM $2
            AND media_path = $3",
        org_id,
        service_instance_id,
        media_path,
    )
    .fetch_optional(pool)
    .await
}
