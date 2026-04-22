//! Background task: keep `service_action_embeddings` in sync with the
//! registry and the DB-backed templates.
//!
//! Runs once at boot (after migrations and the pgvector preflight) and then
//! sleeps until the process restarts — global templates only change on
//! deploy, and DB-tier changes are handled synchronously by the template
//! write-path hooks. The boot pass exists to heal:
//!   - fresh environments (empty embedding table)
//!   - schema upgrades that changed the embedded `source_text` format
//!   - self-hosted deploys where pgvector was added after the fact
//!
//! Backfill is idempotent: we list existing rows per scope, compare
//! `source_text`, and only re-embed the delta. Missing rows are embedded;
//! orphan rows (actions that no longer exist) are deleted in the write
//! path, not here — leftover rows from a deleted template stay until the
//! template is deleted explicitly, matching how the rest of the template
//! system handles cascades.
//!
//! Backfill reads every active template row via a runtime sqlx query
//! (pgvector-adjacent paths opt out of the compile-time macro; see the
//! sibling `service_action_embedding` repo for the rationale).
#![allow(clippy::disallowed_methods)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sqlx::PgPool;

use overslash_core::embeddings::{Embedder, action_source_text};
use overslash_core::registry::ServiceRegistry;
use overslash_db::repos::service_action_embedding;

/// Max items embedded per batch call. Amortizes ONNX per-batch setup cost
/// without blocking the task loop for too long between yields.
const BATCH_SIZE: usize = 32;

/// Entry point invoked from `create_app`. Swallows all errors internally
/// (they're logged) so the search endpoint stays usable while backfill
/// progresses — a half-backfilled vector store still produces meaningful
/// results, just with gaps that the keyword+fuzzy fallback covers.
pub async fn run_once(db: PgPool, registry: Arc<ServiceRegistry>, embedder: Arc<dyn Embedder>) {
    if !embedder.is_enabled() {
        tracing::debug!("embedding backfill skipped: embedder is disabled");
        return;
    }
    let before = service_action_embedding::count_all(&db).await.unwrap_or(-1);

    let global_n = match backfill_global(&db, &registry, embedder.as_ref()).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("global-tier backfill failed: {e}");
            0
        }
    };
    let db_n = match backfill_db_templates(&db, embedder.as_ref()).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("db-template backfill failed: {e}");
            0
        }
    };

    let after = service_action_embedding::count_all(&db).await.unwrap_or(-1);
    tracing::info!(
        "embedding backfill done: global={global_n} db={db_n} table_rows {before} -> {after}"
    );
}

/// Embed the global tier. One scope only (`tier='global'`, org/owner NULL)
/// so the diff is straight: compare existing rows' `source_text` to what
/// the registry would produce now, re-embed the delta.
async fn backfill_global(
    db: &PgPool,
    registry: &ServiceRegistry,
    embedder: &dyn Embedder,
) -> Result<usize, sqlx::Error> {
    let existing =
        service_action_embedding::list_source_texts_for_scope(db, "global", None, None).await?;
    let existing_map: HashMap<(String, String), String> = existing
        .into_iter()
        .map(|e| ((e.template_key, e.action_key), e.source_text))
        .collect();

    let mut pending: Vec<PendingEmbed> = Vec::new();
    for svc in registry.all() {
        for (action_key, action) in svc.actions.iter() {
            let source = action_source_text(
                &svc.display_name,
                svc.description.as_deref(),
                action_key,
                &action.description,
            );
            let is_stale = existing_map
                .get(&(svc.key.clone(), action_key.clone()))
                .map(|prev| prev != &source)
                .unwrap_or(true);
            if is_stale {
                pending.push(PendingEmbed {
                    tier: "global",
                    org_id: None,
                    owner_identity_id: None,
                    template_key: svc.key.clone(),
                    action_key: action_key.clone(),
                    source_text: source,
                });
            }
        }
    }

    embed_and_upsert(db, embedder, &pending).await
}

/// Embed DB-backed templates (org + user tiers). Scope diffing is per
/// `(tier, org_id, owner_identity_id)` so one org's edits don't trip
/// another org's staleness check.
async fn backfill_db_templates(db: &PgPool, embedder: &dyn Embedder) -> Result<usize, sqlx::Error> {
    // Pull every active template row across all orgs. The full-scan is
    // acceptable at boot: the table is small, and the alternative
    // (per-scope queries) duplicates bookkeeping for no real savings.
    let rows = sqlx::query_as::<_, (uuid::Uuid, Option<uuid::Uuid>, String, serde_json::Value)>(
        "SELECT org_id, owner_identity_id, key, openapi FROM service_templates WHERE status = 'active'",
    )
    .fetch_all(db)
    .await?;

    // Pre-fetch per-scope existing embeddings, keyed by a stable scope tuple.
    let mut scope_cache: HashMap<ScopeKey, HashMap<(String, String), String>> = HashMap::new();
    let mut seen_scopes: HashSet<ScopeKey> = HashSet::new();
    for (org_id, owner_identity_id, _, _) in &rows {
        let tier = if owner_identity_id.is_some() {
            "user"
        } else {
            "org"
        };
        seen_scopes.insert(ScopeKey {
            tier,
            org_id: Some(*org_id),
            owner_identity_id: *owner_identity_id,
        });
    }
    for key in &seen_scopes {
        let existing = service_action_embedding::list_source_texts_for_scope(
            db,
            key.tier,
            key.org_id,
            key.owner_identity_id,
        )
        .await?;
        scope_cache.insert(
            key.clone(),
            existing
                .into_iter()
                .map(|e| ((e.template_key, e.action_key), e.source_text))
                .collect(),
        );
    }

    let mut pending: Vec<PendingEmbed> = Vec::new();
    for (org_id, owner_identity_id, key, openapi) in rows {
        let tier = if owner_identity_id.is_some() {
            "user"
        } else {
            "org"
        };
        let scope = ScopeKey {
            tier,
            org_id: Some(org_id),
            owner_identity_id,
        };
        let existing_map = scope_cache.get(&scope).cloned().unwrap_or_default();

        let (def, _warnings) = match overslash_core::openapi::compile_service(&openapi) {
            Ok(d) => d,
            Err(errors) => {
                // Skip — the regular runtime path will log this on every
                // request; backfill shouldn't paper over it either.
                tracing::warn!(
                    "skipping embedding for template '{}' (org={org_id}): compile errors {:?}",
                    key,
                    errors
                );
                continue;
            }
        };
        for (action_key, action) in def.actions.iter() {
            let source = action_source_text(
                &def.display_name,
                def.description.as_deref(),
                action_key,
                &action.description,
            );
            let is_stale = existing_map
                .get(&(def.key.clone(), action_key.clone()))
                .map(|prev| prev != &source)
                .unwrap_or(true);
            if is_stale {
                pending.push(PendingEmbed {
                    tier,
                    org_id: Some(org_id),
                    owner_identity_id,
                    template_key: def.key.clone(),
                    action_key: action_key.clone(),
                    source_text: source,
                });
            }
        }
    }

    embed_and_upsert(db, embedder, &pending).await
}

async fn embed_and_upsert(
    db: &PgPool,
    embedder: &dyn Embedder,
    pending: &[PendingEmbed],
) -> Result<usize, sqlx::Error> {
    let mut written = 0usize;
    for chunk in pending.chunks(BATCH_SIZE) {
        let texts: Vec<&str> = chunk.iter().map(|p| p.source_text.as_str()).collect();
        let vecs = match embedder.embed(&texts) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("embed batch failed ({} items): {e}", chunk.len());
                continue;
            }
        };
        if vecs.len() != chunk.len() {
            // DisabledEmbedder returns `vec![]`, in which case there's
            // nothing to write; any other mismatch is a bug worth logging.
            if !vecs.is_empty() {
                tracing::warn!(
                    "embedder returned {} vectors for {} inputs; skipping batch",
                    vecs.len(),
                    chunk.len()
                );
            }
            continue;
        }
        for (p, embedding) in chunk.iter().zip(vecs) {
            if let Err(e) = service_action_embedding::upsert(
                db,
                p.tier,
                p.org_id,
                p.owner_identity_id,
                &p.template_key,
                &p.action_key,
                &p.source_text,
                embedding,
            )
            .await
            {
                tracing::warn!(
                    "embedding upsert failed for {}/{}: {e}",
                    p.template_key,
                    p.action_key
                );
                continue;
            }
            written += 1;
        }
    }
    Ok(written)
}

/// Synchronous write-path hook: re-embed every action of a single
/// template, purge rows for actions that no longer exist, and upsert the
/// rest. Called from the template create / update / promote handlers so
/// the search index never lags behind what the user just edited.
///
/// No-ops when `embedder.is_enabled()` is false — the endpoint's fallback
/// path covers the missing vectors. All errors are logged and swallowed
/// because refreshing embeddings is never a reason to fail a template
/// write: the user's change landed in the authoritative table, and the
/// index can catch up on the next boot backfill.
pub async fn refresh_template(
    db: &PgPool,
    embedder: &dyn Embedder,
    tier: &'static str,
    org_id: Option<uuid::Uuid>,
    owner_identity_id: Option<uuid::Uuid>,
    def: &overslash_core::types::ServiceDefinition,
) {
    if !embedder.is_enabled() {
        return;
    }

    let action_keys: Vec<String> = def.actions.keys().cloned().collect();
    if let Err(e) = service_action_embedding::delete_actions_not_in(
        db,
        tier,
        org_id,
        owner_identity_id,
        &def.key,
        &action_keys,
    )
    .await
    {
        tracing::warn!(
            "prune stale embeddings failed for {}/{}: {e}",
            def.key,
            tier
        );
    }

    let pending: Vec<PendingEmbed> = def
        .actions
        .iter()
        .map(|(action_key, action)| PendingEmbed {
            tier,
            org_id,
            owner_identity_id,
            template_key: def.key.clone(),
            action_key: action_key.clone(),
            source_text: action_source_text(
                &def.display_name,
                def.description.as_deref(),
                action_key,
                &action.description,
            ),
        })
        .collect();

    if let Err(e) = embed_and_upsert(db, embedder, &pending).await {
        tracing::warn!("template embedding refresh failed for {}: {e}", def.key);
    }
}

/// Synchronous write-path hook: delete every embedding row for a template
/// that was just removed. Mirrors [`refresh_template`] on the other side
/// of the lifecycle.
pub async fn delete_template_embeddings(
    db: &PgPool,
    tier: &'static str,
    org_id: Option<uuid::Uuid>,
    owner_identity_id: Option<uuid::Uuid>,
    template_key: &str,
) {
    if let Err(e) =
        service_action_embedding::delete_template(db, tier, org_id, owner_identity_id, template_key)
            .await
    {
        tracing::warn!(
            "delete embeddings for {}/{} failed: {e}",
            template_key,
            tier
        );
    }
}

struct PendingEmbed {
    tier: &'static str,
    org_id: Option<uuid::Uuid>,
    owner_identity_id: Option<uuid::Uuid>,
    template_key: String,
    action_key: String,
    source_text: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct ScopeKey {
    tier: &'static str,
    org_id: Option<uuid::Uuid>,
    owner_identity_id: Option<uuid::Uuid>,
}
