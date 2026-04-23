//! Vector store for service/action embeddings backing `GET /v1/search`
//! (SPEC §10). Populated by the embedding backfill task on boot and by the
//! template write-path hooks.
//!
//! **Runtime-checked queries.** Unlike the rest of this crate, this module
//! uses `sqlx::query()` / `sqlx::query_as()` instead of the `query_as!`
//! macro. Reasons:
//!   1. The `VECTOR(n)` column type is defined by the pgvector extension,
//!      not core Postgres. sqlx's compile-time macro needs a live schema it
//!      fully understands; pgvector types require explicit adapter shims
//!      that don't interact cleanly with the macro's type inference.
//!   2. Both the extension and the table itself are conditionally present
//!      (migrations 037 / 038 no-op on vanilla Postgres). Compile-time
//!      checks against a DB without pgvector would fail the macro outright.
//!      Runtime queries let the code compile on any Postgres and fail
//!      gracefully at call time — which the endpoint guards behind
//!      `state.embeddings_available` anyway.
//!
//! Integration tests exercise every query path, so the loss of macro
//! checking is covered by test coverage rather than compile-time alone.
#![allow(clippy::disallowed_methods)]

use pgvector::Vector;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// One indexed `(tier, scope, template, action)` pairing. The tier columns
/// are a discriminated union:
///   - tier='global' → `org_id IS NULL`, `owner_identity_id IS NULL`
///   - tier='org'    → `org_id` set,    `owner_identity_id IS NULL`
///   - tier='user'   → both set
#[derive(Debug, Clone)]
pub struct EmbeddingRow {
    pub id: Uuid,
    pub tier: String,
    pub org_id: Option<Uuid>,
    pub owner_identity_id: Option<Uuid>,
    pub template_key: String,
    pub action_key: String,
    pub source_text: String,
    pub embedding: Vec<f32>,
    pub updated_at: OffsetDateTime,
}

/// Minimal projection used by the backfill diff — we only need enough to
/// decide whether to re-embed (compare `source_text`) and to target the
/// right row for upsert.
#[derive(Debug, Clone)]
pub struct EmbeddingStaleCheck {
    pub template_key: String,
    pub action_key: String,
    pub source_text: String,
}

/// A single cosine-ranked hit from [`top_k_cosine`].
#[derive(Debug, Clone)]
pub struct EmbeddingHit {
    pub tier: String,
    pub org_id: Option<Uuid>,
    pub owner_identity_id: Option<Uuid>,
    pub template_key: String,
    pub action_key: String,
    /// `1 - cosine_distance`, so higher is more similar (matches the
    /// endpoint-level convention).
    pub score: f32,
}

/// Upsert a single embedding. `tier` must be one of `'global'`, `'org'`,
/// `'user'`. `org_id` / `owner_identity_id` must match the tier convention
/// documented on [`EmbeddingRow`].
#[allow(clippy::too_many_arguments)]
pub async fn upsert(
    pool: &PgPool,
    tier: &str,
    org_id: Option<Uuid>,
    owner_identity_id: Option<Uuid>,
    template_key: &str,
    action_key: &str,
    source_text: &str,
    embedding: Vec<f32>,
) -> Result<(), sqlx::Error> {
    let vec = Vector::from(embedding);

    // The partial unique indices (see migration 038) can't appear in a
    // single ON CONFLICT target, so branch per tier. Each branch names the
    // right column list for its unique index.
    let sql = match tier {
        "global" => {
            "INSERT INTO service_action_embeddings \
             (tier, org_id, owner_identity_id, template_key, action_key, source_text, embedding) \
             VALUES ('global', NULL, NULL, $1, $2, $3, $4) \
             ON CONFLICT (template_key, action_key) WHERE tier = 'global' DO UPDATE SET \
               source_text = EXCLUDED.source_text, \
               embedding   = EXCLUDED.embedding, \
               updated_at  = NOW()"
        }
        "org" => {
            "INSERT INTO service_action_embeddings \
             (tier, org_id, owner_identity_id, template_key, action_key, source_text, embedding) \
             VALUES ('org', $5, NULL, $1, $2, $3, $4) \
             ON CONFLICT (org_id, template_key, action_key) WHERE tier = 'org' DO UPDATE SET \
               source_text = EXCLUDED.source_text, \
               embedding   = EXCLUDED.embedding, \
               updated_at  = NOW()"
        }
        "user" => {
            "INSERT INTO service_action_embeddings \
             (tier, org_id, owner_identity_id, template_key, action_key, source_text, embedding) \
             VALUES ('user', $5, $6, $1, $2, $3, $4) \
             ON CONFLICT (org_id, owner_identity_id, template_key, action_key) WHERE tier = 'user' DO UPDATE SET \
               source_text = EXCLUDED.source_text, \
               embedding   = EXCLUDED.embedding, \
               updated_at  = NOW()"
        }
        other => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid embedding tier '{other}' (expected global/org/user)"
            )));
        }
    };

    let mut q = sqlx::query(sql)
        .bind(template_key)
        .bind(action_key)
        .bind(source_text)
        .bind(&vec);
    if matches!(tier, "org" | "user") {
        q = q.bind(org_id);
    }
    if tier == "user" {
        q = q.bind(owner_identity_id);
    }
    q.execute(pool).await?;
    Ok(())
}

/// Delete all rows for a given `(tier, template_key)` pair. Used when a
/// template is removed or its key changes. The tier discriminator means
/// deleting one tenant's template never accidentally wipes a shared global
/// embedding.
pub async fn delete_template(
    pool: &PgPool,
    tier: &str,
    org_id: Option<Uuid>,
    owner_identity_id: Option<Uuid>,
    template_key: &str,
) -> Result<u64, sqlx::Error> {
    let result = match tier {
        "global" => {
            sqlx::query(
                "DELETE FROM service_action_embeddings WHERE tier = 'global' AND template_key = $1",
            )
            .bind(template_key)
            .execute(pool)
            .await?
        }
        "org" => {
            sqlx::query(
                "DELETE FROM service_action_embeddings \
                 WHERE tier = 'org' AND org_id = $1 AND template_key = $2",
            )
            .bind(org_id)
            .bind(template_key)
            .execute(pool)
            .await?
        }
        "user" => {
            sqlx::query(
                "DELETE FROM service_action_embeddings \
                 WHERE tier = 'user' AND org_id = $1 AND owner_identity_id = $2 AND template_key = $3",
            )
            .bind(org_id)
            .bind(owner_identity_id)
            .bind(template_key)
            .execute(pool)
            .await?
        }
        other => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid embedding tier '{other}' (expected global/org/user)"
            )));
        }
    };
    Ok(result.rows_affected())
}

/// Delete the embedding rows for actions that no longer exist in a template
/// (after an update removes some action keys). `keep` is the new set of
/// action keys; anything else under `(tier, template_key[, org, owner])`
/// goes away.
pub async fn delete_actions_not_in(
    pool: &PgPool,
    tier: &str,
    org_id: Option<Uuid>,
    owner_identity_id: Option<Uuid>,
    template_key: &str,
    keep: &[String],
) -> Result<u64, sqlx::Error> {
    let result = match tier {
        "global" => {
            sqlx::query(
                "DELETE FROM service_action_embeddings \
                 WHERE tier = 'global' AND template_key = $1 AND action_key <> ALL($2)",
            )
            .bind(template_key)
            .bind(keep)
            .execute(pool)
            .await?
        }
        "org" => {
            sqlx::query(
                "DELETE FROM service_action_embeddings \
                 WHERE tier = 'org' AND org_id = $1 AND template_key = $2 AND action_key <> ALL($3)",
            )
            .bind(org_id)
            .bind(template_key)
            .bind(keep)
            .execute(pool)
            .await?
        }
        "user" => {
            sqlx::query(
                "DELETE FROM service_action_embeddings \
                 WHERE tier = 'user' AND org_id = $1 AND owner_identity_id = $2 \
                   AND template_key = $3 AND action_key <> ALL($4)",
            )
            .bind(org_id)
            .bind(owner_identity_id)
            .bind(template_key)
            .bind(keep)
            .execute(pool)
            .await?
        }
        other => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid embedding tier '{other}' (expected global/org/user)"
            )));
        }
    };
    Ok(result.rows_affected())
}

/// List the `(template_key, action_key, source_text)` triples already stored
/// for one tier + scope. Used by the backfill task to compute the diff: any
/// candidate whose `source_text` differs (or is absent) is re-embedded.
pub async fn list_source_texts_for_scope(
    pool: &PgPool,
    tier: &str,
    org_id: Option<Uuid>,
    owner_identity_id: Option<Uuid>,
) -> Result<Vec<EmbeddingStaleCheck>, sqlx::Error> {
    let rows = match tier {
        "global" => {
            sqlx::query_as::<_, (String, String, String)>(
                "SELECT template_key, action_key, source_text FROM service_action_embeddings \
                 WHERE tier = 'global'",
            )
            .fetch_all(pool)
            .await?
        }
        "org" => {
            sqlx::query_as::<_, (String, String, String)>(
                "SELECT template_key, action_key, source_text FROM service_action_embeddings \
                 WHERE tier = 'org' AND org_id = $1",
            )
            .bind(org_id)
            .fetch_all(pool)
            .await?
        }
        "user" => {
            sqlx::query_as::<_, (String, String, String)>(
                "SELECT template_key, action_key, source_text FROM service_action_embeddings \
                 WHERE tier = 'user' AND org_id = $1 AND owner_identity_id = $2",
            )
            .bind(org_id)
            .bind(owner_identity_id)
            .fetch_all(pool)
            .await?
        }
        other => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid embedding tier '{other}' (expected global/org/user)"
            )));
        }
    };

    Ok(rows
        .into_iter()
        .map(|(t, a, s)| EmbeddingStaleCheck {
            template_key: t,
            action_key: a,
            source_text: s,
        })
        .collect())
}

/// Top-K cosine-similarity retrieval across all tiers visible to the caller.
/// `org_id` scopes org/user-tier results; `owner_identity_id` further
/// restricts user-tier matches to the caller (user-tier rows are private to
/// their owner by design). Global-tier rows are always visible.
///
/// Returns rows ordered by similarity descending (best first). The endpoint
/// reconciles these hits against its candidate list and blends the
/// similarity into the final score.
pub async fn top_k_cosine(
    pool: &PgPool,
    query: Vec<f32>,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    k: i64,
) -> Result<Vec<EmbeddingHit>, sqlx::Error> {
    let vec = Vector::from(query);
    // Three-tier visibility: global (always), org (this org), user (this
    // caller). `IS NOT DISTINCT FROM` makes NULL-aware equality work for
    // the nullable tier columns.
    let rows = sqlx::query_as::<_, (String, Option<Uuid>, Option<Uuid>, String, String, f64)>(
        "SELECT tier, org_id, owner_identity_id, template_key, action_key, \
                1.0 - (embedding <=> $1)::float8 AS score \
         FROM service_action_embeddings \
         WHERE tier = 'global' \
            OR (tier = 'org'  AND org_id = $2) \
            OR (tier = 'user' AND org_id = $2 AND owner_identity_id IS NOT DISTINCT FROM $3) \
         ORDER BY embedding <=> $1 \
         LIMIT $4",
    )
    .bind(&vec)
    .bind(org_id)
    .bind(owner_identity_id)
    .bind(k)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(tier, o, owner, template_key, action_key, score)| EmbeddingHit {
                tier,
                org_id: o,
                owner_identity_id: owner,
                template_key,
                action_key,
                score: score as f32,
            },
        )
        .collect())
}

/// Count rows per tier — used by the backfill task for "how far along are
/// we?" logging and by tests as a smoke check.
pub async fn count_all(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM service_action_embeddings")
        .fetch_one(pool)
        .await?;
    Ok(count)
}
