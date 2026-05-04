//! `GET /v1/search?q=...` — the unified service/action discovery endpoint
//! spec'd in SPEC.md §10. Backs the MCP `overslash_search` tool.
//!
//! Blends three sources of ranking signal:
//!   1. **Keyword + Jaro-Winkler fuzzy** over every visible
//!      `(service, action)` pair (in `overslash-core::search`).
//!   2. **Embedding cosine similarity** via pgvector top-K, when available
//!      (`state.embeddings_available`). Gracefully skipped when the env
//!      flag is off or the extension isn't installed.
//!   3. **Post-rank bonuses**: a connected-instance bonus (floats up actions
//!      the caller can run right now) and a small read-safer bonus.
//!
//! Candidate visibility matches the other routes: identity-bound keys
//! apply group-ceiling filtering the same way `list_services` does; org-
//! level keys bypass. See `routes/services.rs::list_services` for the
//! underlying scope machinery reused here.

use std::collections::{HashMap, HashSet};

use axum::{Json, Router, extract::Query, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::search::{Candidate, MIN_SCORE, apply_post_bonuses, keyword_fuzzy_score};
use overslash_core::types::{Risk, ServiceAuth, ServiceDefinition};
use overslash_db::repos::{org as org_repo, service_action_embedding, service_template};
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::AuthContext,
    services::group_ceiling,
};

/// Weight split when blending keyword+fuzzy with embedding cosine. Biased
/// toward embeddings because that's the whole point of natural-language
/// queries, but keyword still carries meaningful signal for exact matches
/// like `"stripe"` or `"list_repos"`.
const KEYWORD_WEIGHT: f32 = 0.4;
const EMBEDDING_WEIGHT: f32 = 0.6;

/// Default `limit` when the caller doesn't pass one. Deliberately small so
/// agents get a short actionable list rather than a dump of the whole
/// registry.
const DEFAULT_LIMIT: usize = 20;
/// Upper bound on `limit`. Caps the response size even if an agent asks for
/// more — at this corpus size 100 is already well past the point of
/// diminishing returns.
const MAX_LIMIT: usize = 100;
/// Top-K fetched from pgvector. Larger than MAX_LIMIT because we still
/// re-rank in the endpoint (and filter by visibility the SQL couldn't
/// enforce cleanly, e.g. hidden global templates).
const EMBEDDING_CANDIDATES: i64 = 50;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/search", get(search))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    #[serde(default)]
    limit: Option<usize>,
    /// Opt-in: also surface un-connected catalog services. The default
    /// (`false`) keeps the agent-facing tool focused on what the caller can
    /// actually call right now; setting this to `true` brings the global
    /// + org catalog back into both browse and keyword modes. See SPEC §10.
    #[serde(default)]
    include_catalog: bool,
}

#[derive(Serialize)]
struct SearchResponse {
    query: String,
    results: Vec<SearchResult>,
}

#[derive(Serialize)]
struct SearchResult {
    /// Instance name — the value to pass directly as `overslash_call.service`.
    /// Absent for catalog rows (`setup_required: true`), where no instance
    /// is configured for the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    /// Template key. Always present, for traceability and to let agents
    /// recognise that two rows (e.g. `gmail_work` and `gmail_personal`) come
    /// from the same template.
    template: String,
    service_display_name: String,
    /// OAuth account identifier sourced from `connections.account_email`
    /// (e.g. `alice@gmail.com`). Hoisted to the top level since each row is
    /// already a single instance. Absent for api-key rows and for OAuth
    /// connections whose userinfo lookup didn't return an email.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_email: Option<String>,
    /// Variable name of the secret backing an api-key instance — the label
    /// only, never the value. Hoisted to the top level since each row is a
    /// single instance. Absent for OAuth rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_name: Option<String>,
    /// Action fields and `score` are absent in browse mode (empty query),
    /// where each result represents a service-level entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<Risk>,
    tier: String,
    auth: AuthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f32>,
    /// `true` for catalog rows whose template has no configured instance for
    /// the caller. Only present when `include_catalog=true` in the request.
    /// Agents must call `overslash_auth.create_service_from_template` before
    /// this row becomes callable.
    #[serde(skip_serializing_if = "Option::is_none")]
    setup_required: Option<bool>,
}

#[derive(Serialize, Clone)]
struct AuthStatus {
    /// `"oauth"` or `"api_key"`. Mirrors `ServiceAuth` so agents don't have
    /// to crack open the template themselves.
    #[serde(rename = "type")]
    kind: String,
    /// OAuth provider key when `kind == "oauth"`. Absent for api-key auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    /// `true` when this row represents a configured instance the caller can
    /// call now; `false` for `setup_required` catalog rows.
    connected: bool,
}

/// Per-instance data carried from `collect_visible_templates` into the
/// fan-out loops. One of these becomes one search result row.
#[derive(Clone)]
struct InstanceRow {
    /// The instance's runtime name — passed verbatim as `overslash_call.service`.
    name: String,
    /// OAuth account identifier (when applicable).
    account_email: Option<String>,
    /// Secret-name label for api-key instances (when applicable).
    secret_name: Option<String>,
}

async fn search(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Query(params): Query<SearchQuery>,
) -> Result<Json<SearchResponse>> {
    let q = params.q.trim();

    let (templates, instances_by_template) =
        collect_visible_templates(&state, &auth, &scope).await?;

    // Default behavior: hide templates with no active instance bound to
    // the caller. `include_catalog=true` brings the global/org catalog
    // back. Filter applies to both browse and keyword modes.
    let template_iter: Box<dyn Iterator<Item = &TemplateCandidate>> = if params.include_catalog {
        Box::new(templates.iter())
    } else {
        Box::new(
            templates
                .iter()
                .filter(|t| instances_by_template.contains_key(&t.def.key)),
        )
    };
    let visible_templates: Vec<&TemplateCandidate> = template_iter.collect();

    if q.is_empty() {
        overslash_metrics::search::record_query("browse", "ok");
        // Browse mode: list every visible service with no actions, fanned
        // out one row per instance so each row is directly callable. The
        // catalog is bounded (~dozens of templates × a few instances each),
        // so we deliberately skip the limit clamp — truncating "show me
        // everything available" defeats the use case.
        let mut results: Vec<SearchResult> = Vec::new();
        for t in &visible_templates {
            let connected_instances = instances_by_template
                .get(&t.def.key)
                .cloned()
                .unwrap_or_default();
            if connected_instances.is_empty() {
                // Un-connected catalog row — only emitted under
                // include_catalog=true (the visible_templates filter
                // already enforced that).
                if !params.include_catalog {
                    continue;
                }
                results.push(SearchResult {
                    service: None,
                    template: t.def.key.clone(),
                    service_display_name: t.def.display_name.clone(),
                    account_email: None,
                    secret_name: None,
                    action: None,
                    description: None,
                    risk: None,
                    tier: t.tier.into(),
                    auth: build_auth_status(&t.def, false),
                    score: None,
                    setup_required: Some(true),
                });
            } else {
                for inst in connected_instances {
                    results.push(SearchResult {
                        service: Some(inst.name),
                        template: t.def.key.clone(),
                        service_display_name: t.def.display_name.clone(),
                        account_email: inst.account_email,
                        secret_name: inst.secret_name,
                        action: None,
                        description: None,
                        risk: None,
                        tier: t.tier.into(),
                        auth: build_auth_status(&t.def, true),
                        score: None,
                        setup_required: None,
                    });
                }
            }
        }
        // Connected-first, then alphabetical by display name, then by
        // instance `service` to keep fan-out rows of the same template in a
        // stable order. Mirrors the CONNECTED_BONUS intent in scored mode.
        results.sort_by(|a, b| {
            b.auth
                .connected
                .cmp(&a.auth.connected)
                .then_with(|| {
                    a.service_display_name
                        .to_lowercase()
                        .cmp(&b.service_display_name.to_lowercase())
                })
                .then_with(|| a.service.cmp(&b.service))
        });
        return Ok(Json(SearchResponse {
            query: q.to_string(),
            results,
        }));
    }

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    // --- Embedding cosine retrieval (optional) ---
    // Keyed by (tier, template_key, action_key) so we can merge with the
    // keyword score per-candidate without ambiguity. A template key alone
    // isn't unique across tiers when an org shadows a global.
    let mut emb_scores: HashMap<(String, String, String), f32> = HashMap::new();
    if state.embeddings_available && state.embedder.is_enabled() {
        match state.embedder.embed(&[q]) {
            Ok(vecs) if !vecs.is_empty() => {
                match service_action_embedding::top_k_cosine(
                    &state.db,
                    vecs[0].clone(),
                    auth.org_id,
                    auth.identity_id,
                    EMBEDDING_CANDIDATES,
                )
                .await
                {
                    Ok(hits) => {
                        for h in hits {
                            emb_scores.insert(
                                (h.tier, h.template_key, h.action_key),
                                h.score.clamp(0.0, 1.0),
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("pgvector top-k failed, falling back: {e}");
                    }
                }
            }
            Ok(_) => {
                // Empty result from embedder — treat as disabled for this
                // request; keyword+fuzzy still runs below.
            }
            Err(e) => {
                tracing::warn!("query embedding failed, falling back: {e}");
            }
        }
    }

    // --- Score every (template, action) candidate, then fan-out per instance ---
    let mut scored: Vec<SearchResult> = Vec::new();
    for t in &visible_templates {
        let connected_instances = instances_by_template
            .get(&t.def.key)
            .cloned()
            .unwrap_or_default();
        let connected = !connected_instances.is_empty();
        let auth_status = build_auth_status(&t.def, connected);

        for (action_key, action) in t.def.actions.iter() {
            let cand = Candidate {
                service: &t.def,
                action_key,
                action,
            };
            let kw = keyword_fuzzy_score(q, &cand);
            let emb = emb_scores
                .get(&(t.tier.to_string(), t.def.key.clone(), action_key.clone()))
                .copied()
                .unwrap_or(0.0);

            // When the embedder didn't contribute (disabled / unavailable /
            // query out of domain), blend to pure keyword — otherwise
            // embedding-zero drags every result below MIN_SCORE.
            let raw = if emb > 0.0 {
                KEYWORD_WEIGHT * kw + EMBEDDING_WEIGHT * emb
            } else {
                kw
            };
            let final_score = apply_post_bonuses(raw, connected, action.risk);
            if final_score < MIN_SCORE {
                continue;
            }

            if connected_instances.is_empty() {
                // Catalog candidate — only emit when include_catalog=true
                // (visible_templates already enforced that filter; this
                // branch is the un-connected case under that flag).
                if !params.include_catalog {
                    continue;
                }
                scored.push(SearchResult {
                    service: None,
                    template: t.def.key.clone(),
                    service_display_name: t.def.display_name.clone(),
                    account_email: None,
                    secret_name: None,
                    action: Some(action_key.clone()),
                    description: Some(action.description.clone()),
                    risk: Some(action.risk),
                    tier: t.tier.into(),
                    auth: auth_status.clone(),
                    score: Some(final_score),
                    setup_required: Some(true),
                });
            } else {
                // Fan-out: one row per (action × instance). Score is the
                // same across instances of the same (template, action) —
                // tie-break sort below stabilises by service name.
                for inst in &connected_instances {
                    scored.push(SearchResult {
                        service: Some(inst.name.clone()),
                        template: t.def.key.clone(),
                        service_display_name: t.def.display_name.clone(),
                        account_email: inst.account_email.clone(),
                        secret_name: inst.secret_name.clone(),
                        action: Some(action_key.clone()),
                        description: Some(action.description.clone()),
                        risk: Some(action.risk),
                        tier: t.tier.into(),
                        auth: auth_status.clone(),
                        score: Some(final_score),
                        setup_required: None,
                    });
                }
            }
        }
    }

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.service.cmp(&b.service))
    });
    scored.truncate(limit);

    let mode = if !emb_scores.is_empty() {
        "hybrid"
    } else {
        "keyword"
    };
    overslash_metrics::search::record_query(mode, "ok");
    Ok(Json(SearchResponse {
        query: q.to_string(),
        results: scored,
    }))
}

/// Resolves the set of visible service templates and active instances for
/// the caller, applying the same global-tier filter and group-ceiling
/// machinery as `routes/services.rs::list_services`.
async fn collect_visible_templates(
    state: &AppState,
    auth: &AuthContext,
    scope: &OrgScope,
) -> Result<(Vec<TemplateCandidate>, HashMap<String, Vec<InstanceRow>>)> {
    let global_filter = visible_global_filter(state, auth.org_id).await?;
    let user_templates_allowed = org_repo::get_allow_user_templates(&state.db, auth.org_id)
        .await?
        .unwrap_or(false);

    // Visibility goes through `get_visible_service_ids` for any identity-bound
    // call so the search/list view stays consistent with what `load_ceiling`
    // enforces at action time. Org-level keys (no identity) bypass — they see
    // every service in the org.
    let (ceiling_user_id, visible_instance_ids) = if let Some(identity_id) = auth.identity_id {
        let ceiling_user_id = group_ceiling::resolve_ceiling_user_id(scope, identity_id).await?;
        let visible_ids = scope.get_visible_service_ids(ceiling_user_id).await?;
        (Some(ceiling_user_id), Some(visible_ids))
    } else {
        (None, None)
    };

    let mut templates: Vec<TemplateCandidate> = Vec::new();

    for svc in state.registry.all() {
        if !is_global_visible(&global_filter, &svc.key) {
            continue;
        }
        templates.push(TemplateCandidate {
            tier: "global",
            def: svc.clone(),
        });
    }

    for t in service_template::list_available(&state.db, auth.org_id, auth.identity_id).await? {
        let is_user_tier = t.owner_identity_id.is_some();
        if is_user_tier && !user_templates_allowed {
            continue;
        }
        let (def, _warnings) =
            overslash_core::openapi::compile_service(&t.openapi).map_err(|errors| {
                AppError::Internal(format!(
                    "template '{}' failed to compile: {errors:?}",
                    t.key
                ))
            })?;
        templates.push(TemplateCandidate {
            tier: if is_user_tier { "user" } else { "org" },
            def,
        });
    }

    let instances = scope
        .list_available_service_instances_with_groups(
            auth.identity_id,
            ceiling_user_id,
            visible_instance_ids.as_deref(),
        )
        .await?;

    // Batch-load connections so we can surface `account_email` per
    // instance without an N+1. Org-tier connections (no owning identity)
    // still flow through the same scope-checked fetch.
    let connection_ids: Vec<Uuid> = instances
        .iter()
        .filter_map(|r| r.connection_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let connections_by_id = scope.get_connections_by_ids(&connection_ids).await?;

    let mut instances_by_template: HashMap<String, Vec<InstanceRow>> = HashMap::new();
    for r in instances {
        if r.status != "active" {
            continue;
        }
        let account_email = r
            .connection_id
            .and_then(|id| connections_by_id.get(&id))
            .and_then(|c| c.account_email.clone());
        instances_by_template
            .entry(r.template_key.clone())
            .or_default()
            .push(InstanceRow {
                name: r.name,
                account_email,
                secret_name: r.secret_name,
            });
    }

    Ok((templates, instances_by_template))
}

struct TemplateCandidate {
    tier: &'static str,
    def: ServiceDefinition,
}

fn build_auth_status(def: &ServiceDefinition, connected: bool) -> AuthStatus {
    // Pick the first declared auth method as the primary face the caller
    // sees. Templates that mix auth methods (rare) still surface here with
    // the preferred one first — exactly how the dashboard displays them.
    let (kind, provider) = match def.auth.first() {
        Some(ServiceAuth::OAuth { provider, .. }) => ("oauth".into(), Some(provider.clone())),
        Some(ServiceAuth::ApiKey { .. }) => ("api_key".into(), None),
        None => ("none".into(), None),
    };
    AuthStatus {
        kind,
        provider,
        connected,
    }
}

// Reproduce the global-template visibility filter used by routes/templates.rs.
// Kept inline (not imported) to avoid cross-route coupling; the logic is
// two lines of SQL wrapped in a hash-set check.
async fn visible_global_filter(state: &AppState, org_id: Uuid) -> Result<Option<HashSet<String>>> {
    let enabled = org_repo::get_global_templates_enabled(&state.db, org_id)
        .await?
        .unwrap_or(true);
    if enabled {
        return Ok(None);
    }
    let keys =
        overslash_db::repos::enabled_global_template::list_enabled_keys(&state.db, org_id).await?;
    Ok(Some(keys.into_iter().collect()))
}

fn is_global_visible(filter: &Option<HashSet<String>>, key: &str) -> bool {
    match filter {
        None => true,
        Some(set) => set.contains(key),
    }
}
