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
use overslash_core::types::{DeclaredRisk, ServiceAction, ServiceAuth, ServiceDefinition};
use overslash_db::repos::{org as org_repo, service_action_embedding, service_template};
use overslash_db::scopes::{OrgScope, UserScope};

use crate::{
    AppState,
    error::Result,
    extractors::{AuthContext, ReqExt},
    services::group_ceiling,
    services::platform_services::{
        ScopeCoverage, ScopeKnowledge, action_scope_coverage, template_oauth_provider,
    },
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
    /// Comma-separated list of services to omit from results. Each entry is
    /// matched against both the instance name (`service` in the response,
    /// e.g. `gmail_work`) and the template key (e.g. `gmail`). Whitespace
    /// around each entry is trimmed; empty entries are ignored. Applied
    /// before scoring + truncation so excluded rows don't displace useful
    /// ones inside the `limit` window.
    #[serde(default)]
    exclude: Option<String>,
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
    /// already a single instance. Absent for secret-based rows and for OAuth
    /// connections whose userinfo lookup didn't return an email.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_email: Option<String>,
    /// Variable name of the secret backing a secret-based instance — the label
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
    risk: Option<DeclaredRisk>,
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
    /// Per-action OAuth scope coverage for a connected instance:
    /// `needs_reconnect` when the bound connection's granted scopes don't cover
    /// this action (calling it will 403 with `missing_scopes`), `unknown` when
    /// the connection's scopes weren't recorded, `covered` otherwise. Only
    /// present on action rows of OAuth services whose action declares scopes —
    /// lets an agent reconnect at discovery time instead of after a failed call.
    #[serde(skip_serializing_if = "Option::is_none")]
    scope_coverage: Option<ScopeCoverage>,
    /// The missing-scope delta when `scope_coverage == needs_reconnect`. Empty
    /// (and omitted) otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_scopes: Vec<String>,
    /// The action's caller-supplied parameter contract — what may be passed
    /// in `overslash_call.params`. Present on action rows, empty (and
    /// omitted) in browse mode, where the row is service-level.
    ///
    /// Before this existed, an action's `description` was the only string
    /// about it that ever reached the model, so a paging parameter a
    /// template declared was undiscoverable unless its prose happened to
    /// restate it — and an agent facing a list endpoint had no way to see
    /// that a narrower call was available.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    params: Vec<ParamInfo>,
    /// Whether this action declares `x-overslash-pagination` — that it returns
    /// one page of a larger collection, and that the result will carry a
    /// `_pagination.next` naming the call for the page after it.
    ///
    /// A bare boolean, and no more. `params` one field up already shows the
    /// page-size parameter and the bound it defaults to, so spelling the
    /// mechanism out again here would be paid for on every row of a fan-out
    /// that reaches a hundred of them. What the caller cannot get from
    /// `params` is the fact that following pages is *possible at all* without
    /// inferring it from a parameter's name — which is the one bit this adds.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    paginated: bool,
}

/// The model-facing projection of an [`ServiceAction`] parameter.
///
/// Deliberately not `ActionParam` itself: that type also carries `resolve`,
/// `sql_field`, `sql_database` and `instance_config`, which are gateway
/// plumbing the caller neither supplies nor benefits from seeing.
#[derive(Serialize)]
struct ParamInfo {
    name: String,
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    param_type: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    required: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<serde_json::Value>,
}

/// Longest parameter description carried into a search result.
///
/// Every row in a response holds up to this much per parameter, so the cap
/// is a context-budget decision, not a display one. The widest action in the
/// shipped registry declares 10 parameters, which bounds a row's parameter
/// block at roughly 2 KB and a default 20-row response well under what the
/// action's own descriptions already cost.
const MAX_PARAM_DESCRIPTION_CHARS: usize = 160;

/// Project an action's parameters for the model.
///
/// Ordering is explicit — required first, then alphabetical — because
/// `ServiceAction.params` is a `HashMap`, and emitting its iteration order
/// would make byte-identical requests return differently-ordered JSON.
/// Required-first also front-loads what the caller cannot omit.
fn param_infos(action: &ServiceAction) -> Vec<ParamInfo> {
    let mut out: Vec<ParamInfo> = action
        .params
        .iter()
        // `instance-config` params are pinned per service instance by an org
        // admin and merged in under the caller's args at execution time. A
        // caller has no business supplying them, so listing them here would
        // only invite a wrong one.
        .filter(|(_, p)| !p.instance_config)
        .map(|(name, p)| ParamInfo {
            name: name.clone(),
            param_type: p.param_type.clone(),
            required: p.required,
            description: clamp_chars(&p.description, MAX_PARAM_DESCRIPTION_CHARS),
            enum_values: p.enum_values.clone(),
            default: p.default.clone(),
        })
        .collect();
    out.sort_by(|a, b| {
        b.required
            .cmp(&a.required)
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// Truncate `s` to at most `max` characters, appending an ellipsis when it
/// actually cut. Cuts at a char *index* rather than a byte index — `&s[..n]`
/// panics mid-codepoint, and template descriptions are exactly the strings
/// that carry non-ASCII.
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_string(),
    }
}

#[derive(Serialize, Clone)]
struct AuthStatus {
    /// `"oauth"` or `"secret"`. Mirrors `ServiceAuth` so agents don't have
    /// to crack open the template themselves.
    ///
    /// This string is hand-built, not derived from `ServiceAuth`'s serde
    /// tag, so `ServiceAuth::Secret`'s `alias = "api_key"` does NOT apply:
    /// it only rescues *inbound* parsing. Outbound, this field emits
    /// `"secret"` where it used to emit `"api_key"` — a deliberate break for
    /// any client branching on the old discriminant. Agents read the current
    /// vocabulary from SKILL.md, and the dashboard ships with the API.
    #[serde(rename = "type")]
    kind: String,
    /// OAuth provider key when `kind == "oauth"`. Absent for secret-based auth.
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
    /// Secret-name label for secret-based instances (when applicable).
    secret_name: Option<String>,
    /// Granted-scope knowledge of the connection the exec path would use for
    /// this instance (explicit binding, else owner-provider auto-resolve),
    /// resolved the same way `list_services` derives `credentials_status`.
    /// Drives per-action `scope_coverage`. See [`InstanceScopes`].
    scopes: InstanceScopes,
    /// This instance's MCP resync result, if any. Overlaid on the template's
    /// authored tools so tools discovered on the instance become searchable —
    /// visibility-scoped, since only instances the caller can see reach here.
    discovered_tools: Option<Vec<serde_json::Value>>,
}

/// Owned mirror of [`ScopeKnowledge`] carried per instance from
/// `collect_visible_templates` into the fan-out loop.
#[derive(Clone)]
enum InstanceScopes {
    /// No connection bound and none auto-resolves.
    NoConnection,
    /// A connection exists but its granted scopes weren't recorded.
    Unknown,
    /// The known granted scope set (possibly empty).
    Known(Vec<String>),
}

impl InstanceScopes {
    fn from_recorded(scopes: Option<&[String]>) -> Self {
        match scopes {
            Some(s) => InstanceScopes::Known(s.to_vec()),
            None => InstanceScopes::Unknown,
        }
    }

    fn knowledge(&self) -> ScopeKnowledge<'_> {
        match self {
            InstanceScopes::NoConnection => ScopeKnowledge::NoConnection,
            InstanceScopes::Unknown => ScopeKnowledge::Unknown,
            InstanceScopes::Known(v) => ScopeKnowledge::Known(v),
        }
    }
}

async fn search(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    Query(params): Query<SearchQuery>,
) -> Result<Json<SearchResponse>> {
    let q = params.q.trim();

    let (templates, mut instances_by_template) =
        collect_visible_templates(&state, &ext, &auth, &scope).await?;

    // Parse `exclude` once. Entries match against either template key or
    // instance name (callers don't always know which level they want, and
    // the two namespaces don't collide in practice).
    let excluded: HashSet<String> = params
        .exclude
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    // Drop excluded instances per-template. Track templates whose entire
    // instance set was wiped by an instance-name exclusion — under
    // `include_catalog=true` those would otherwise fall back to a
    // `setup_required` catalog row, contradicting the user's intent to
    // hide the service entirely.
    let mut emptied_by_instance_exclude: HashSet<String> = HashSet::new();
    if !excluded.is_empty() {
        for (template_key, instances) in instances_by_template.iter_mut() {
            let had_instances = !instances.is_empty();
            instances.retain(|inst| !excluded.contains(&inst.name));
            if had_instances && instances.is_empty() {
                emptied_by_instance_exclude.insert(template_key.clone());
            }
        }
        instances_by_template.retain(|_, v| !v.is_empty());
    }

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
    let visible_templates: Vec<&TemplateCandidate> = template_iter
        .filter(|t| !excluded.contains(&t.def.key))
        .filter(|t| !emptied_by_instance_exclude.contains(&t.def.key))
        // `x-overslash-hidden` templates are not advertised to agents: drop
        // their un-instantiated catalog rows. Connected instances still
        // surface — an org that deliberately set one up keeps using it.
        .filter(|t| !t.def.hidden || instances_by_template.contains_key(&t.def.key))
        .collect();

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
                    scope_coverage: None,
                    missing_scopes: Vec::new(),
                    params: Vec::new(),
                    paginated: false,
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
                        // Browse rows are service-level (no action) — coverage is
                        // per-action, so nothing to annotate here.
                        scope_coverage: None,
                        missing_scopes: Vec::new(),
                        // Likewise: the parameter contract is per-action.
                        params: Vec::new(),
                        paginated: false,
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
                    state.db(&ext),
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
            let final_score = apply_post_bonuses(raw, connected, action.risk.display_risk());
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
                    // Catalog rows have no connection; "needs setup" already
                    // says it's not callable — don't pile on Unknown coverage.
                    scope_coverage: None,
                    missing_scopes: Vec::new(),
                    params: param_infos(action),
                    paginated: action.pagination.is_some(),
                });
            } else {
                // Fan-out: one row per (action × instance). Score is the
                // same across instances of the same (template, action) —
                // tie-break sort below stabilises by service name.
                for inst in &connected_instances {
                    // Per-action coverage, but only for actions that actually
                    // declare scopes (OAuth-secured). Unscoped/secret-based actions
                    // leave the fields absent.
                    let (scope_coverage, missing_scopes) = if action.required_scopes.is_empty() {
                        (None, Vec::new())
                    } else {
                        let (c, m) = action_scope_coverage(action, inst.scopes.knowledge());
                        (Some(c), m)
                    };
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
                        scope_coverage,
                        missing_scopes,
                        params: param_infos(action),
                        paginated: action.pagination.is_some(),
                    });
                }
            }
        }

        // Second pass: tools discovered on an *instance* (via MCP resync) that
        // the template doesn't declare. Only connected/visible instances reach
        // here, so a caller without access to an instance never sees its
        // instance-only tools. Instance-only tools have no template-scoped
        // embedding row, so they score on the keyword/fuzzy path.
        for inst in &connected_instances {
            let Some(discovered) = inst.discovered_tools.as_ref() else {
                continue;
            };
            let mut inst_def = t.def.clone();
            // Calls the core overlay directly rather than the
            // `overlay_instance_discovered_tools` row wrapper: search carries a
            // projected `InstanceRow`, not a `ServiceInstanceRow`.
            overslash_core::openapi::overlay_discovered_tools(&mut inst_def, discovered);
            for (action_key, action) in inst_def.actions.iter() {
                if t.def.actions.contains_key(action_key) {
                    // Already scored + emitted in the template loop above.
                    continue;
                }
                let cand = Candidate {
                    service: &inst_def,
                    action_key,
                    action,
                };
                let kw = keyword_fuzzy_score(q, &cand);
                let emb = emb_scores
                    .get(&(t.tier.to_string(), t.def.key.clone(), action_key.clone()))
                    .copied()
                    .unwrap_or(0.0);
                let raw = if emb > 0.0 {
                    KEYWORD_WEIGHT * kw + EMBEDDING_WEIGHT * emb
                } else {
                    kw
                };
                let final_score = apply_post_bonuses(raw, connected, action.risk.display_risk());
                if final_score < MIN_SCORE {
                    continue;
                }
                let (scope_coverage, missing_scopes) = if action.required_scopes.is_empty() {
                    (None, Vec::new())
                } else {
                    let (c, m) = action_scope_coverage(action, inst.scopes.knowledge());
                    (Some(c), m)
                };
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
                    scope_coverage,
                    missing_scopes,
                    params: param_infos(action),
                    paginated: action.pagination.is_some(),
                });
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
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    scope: &OrgScope,
) -> Result<(Vec<TemplateCandidate>, HashMap<String, Vec<InstanceRow>>)> {
    let global_filter = visible_global_filter(state, ext, auth.org_id).await?;
    let user_templates_allowed = org_repo::get_allow_user_templates(state.db(ext), auth.org_id)
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

    for t in service_template::list_available(state.db(ext), auth.org_id, auth.identity_id).await? {
        let is_user_tier = t.owner_identity_id.is_some();
        if is_user_tier && !user_templates_allowed {
            continue;
        }
        // Resolve through the layered-template fold so a derived layer's masked
        // surface (and hidden actions) are what search advertises.
        let def = crate::services::template_resolve::resolve_definition(
            state.db(ext),
            &state.registry,
            auth.org_id,
            auth.identity_id,
            &t.key,
        )
        .await?;
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

    // Provider key per template (OAuth templates only), so instances without an
    // explicit connection binding can auto-resolve their owner-provider
    // connection — the same connection the exec path / scope-gate would pick.
    let provider_by_template: HashMap<&str, &str> = templates
        .iter()
        .filter_map(|t| template_oauth_provider(&t.def).map(|p| (t.def.key.as_str(), p)))
        .collect();

    // Auto-resolve owner-provider connections for instances with no explicit
    // binding, mirroring `kernel_list_services`. Deduped by (owner, provider).
    let mut conn_by_owner_provider: HashMap<(Uuid, String), Option<Vec<String>>> = HashMap::new();
    let mut looked_up: HashSet<(Uuid, String)> = HashSet::new();
    for r in &instances {
        if r.status != "active" || r.connection_id.is_some() {
            continue;
        }
        let (Some(owner), Some(provider)) = (
            r.owner_identity_id,
            provider_by_template.get(r.template_key.as_str()).copied(),
        ) else {
            continue;
        };
        let key = (owner, provider.to_string());
        if !looked_up.insert(key.clone()) {
            continue;
        }
        if let Ok(Some(conn)) = UserScope::new(auth.org_id, owner, scope.db().clone())
            .find_my_connection_by_provider(provider)
            .await
        {
            conn_by_owner_provider.insert(key, conn.scopes);
        }
    }

    // Templates that name an identity-bearing config var (`identity: true`),
    // so a secret-based instance can report which account it speaks for.
    let identity_key_by_template: HashMap<&str, &str> = templates
        .iter()
        .filter_map(|t| t.def.identity_config_key().map(|k| (t.def.key.as_str(), k)))
        .collect();

    let mut instances_by_template: HashMap<String, Vec<InstanceRow>> = HashMap::new();
    for r in instances {
        if r.status != "active" {
            continue;
        }
        let bound_conn = r.connection_id.and_then(|id| connections_by_id.get(&id));
        // A bound OAuth connection is authoritative — it is the account the
        // call actually authenticates as. The config value is the fallback for
        // secret-based instances, which have no connection to ask.
        let account_email = bound_conn
            .and_then(|c| c.account_email.clone())
            .or_else(|| {
                let key = identity_key_by_template.get(r.template_key.as_str())?;
                r.config
                    .0
                    .get(*key)
                    .map(String::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string)
            });
        let scopes = if let Some(cid) = r.connection_id {
            match connections_by_id.get(&cid) {
                Some(c) => InstanceScopes::from_recorded(c.scopes.as_deref()),
                None => InstanceScopes::NoConnection,
            }
        } else if let (Some(owner), Some(provider)) = (
            r.owner_identity_id,
            provider_by_template.get(r.template_key.as_str()).copied(),
        ) {
            match conn_by_owner_provider.get(&(owner, provider.to_string())) {
                Some(opt) => InstanceScopes::from_recorded(opt.as_deref()),
                None => InstanceScopes::NoConnection,
            }
        } else {
            InstanceScopes::NoConnection
        };
        instances_by_template
            .entry(r.template_key.clone())
            .or_default()
            .push(InstanceRow {
                name: r.name,
                account_email,
                secret_name: r.secret_name,
                scopes,
                discovered_tools: r.discovered_tools.map(|j| j.0),
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
        Some(ServiceAuth::Secret { .. }) => ("secret".into(), None),
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
async fn visible_global_filter(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
) -> Result<Option<HashSet<String>>> {
    let enabled = org_repo::get_global_templates_enabled(state.db(ext), org_id)
        .await?
        .unwrap_or(true);
    if enabled {
        return Ok(None);
    }
    let keys =
        overslash_db::repos::enabled_global_template::list_enabled_keys(state.db(ext), org_id)
            .await?;
    Ok(Some(keys.into_iter().collect()))
}

fn is_global_visible(filter: &Option<HashSet<String>>, key: &str) -> bool {
    match filter {
        None => true,
        Some(set) => set.contains(key),
    }
}
