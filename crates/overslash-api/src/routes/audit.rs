use std::collections::HashMap;

use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_core::types::service::Risk;
use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditFilter;

use crate::{AppState, error::AppError, error::Result};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/audit", get(query_audit))
}

#[derive(Serialize)]
struct AuditEntry {
    id: Uuid,
    identity_id: Option<Uuid>,
    /// The actor's name **as recorded on the row** — the name they had when
    /// they acted, not their current one (D56). Falls back to the live name
    /// for rows written before migration 109, and stays populated after the
    /// identity is deleted, which the old live lookup could not do.
    identity_name: Option<String>,
    /// Recorded name of the root user of the actor's chain. Same historical
    /// semantics as `identity_name`; the User column falls back to it when the
    /// identity can no longer be resolved live.
    owner_user_name: Option<String>,
    /// SPIFFE-style hierarchical path of the actor identity, e.g.
    /// `spiffe://acme/user/alice/agent/henry`. Null when the chain could not
    /// be resolved (deleted identity, unknown org).
    identity_path: Option<String>,
    /// Identity ids for each `(kind, name)` unit in `identity_path`, in the
    /// same order. Excludes the org slug. Empty when `identity_path` is null.
    identity_path_ids: Vec<Uuid>,
    action: String,
    description: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<Uuid>,
    detail: serde_json::Value,
    ip_address: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// Set when the request was made via `X-Overslash-As` impersonation.
    impersonated_by_identity_id: Option<Uuid>,
    impersonated_by_name: Option<String>,
    /// SPIFFE-style path for the impersonator, when present. Same shape as
    /// `identity_path`.
    impersonated_by_path: Option<String>,
    impersonated_by_path_ids: Vec<Uuid>,
    /// System-derived metadata tags. Empty for events outside the
    /// action/approval path.
    tags: Vec<String>,
    /// Effective risk of the gated call — `read`, `write` or `delete`. Null for
    /// events outside the action/approval path, and for history predating the
    /// `risk:` tag.
    risk: Option<String>,
}

#[derive(serde::Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    /// Legacy offset pagination. Still supported, but `OFFSET n` walks
    /// `n + limit` index entries, so paging a long log with it costs O(pages²)
    /// over a session. Prefer the `before` / `before_id` cursor.
    #[serde(default)]
    offset: i64,
    /// Keyset cursor: `created_at` of the last row already seen. Combined with
    /// `before_id` it returns the next page in `(created_at DESC, id DESC)`
    /// order at constant cost, whatever the depth.
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    before: Option<OffsetDateTime>,
    /// Tiebreaker for the cursor: `id` of the last row already seen. Rows
    /// written in one transaction share a timestamp, so without it a cursor at
    /// that boundary would skip or repeat them.
    before_id: Option<Uuid>,
    action: Option<String>,
    resource_type: Option<String>,
    identity_id: Option<Uuid>,
    /// Free-text search over action, description and identity name. Comma
    /// separated, and every term must match (AND) — the same convention as
    /// `tag` and `identity_kind`, so the search bar's text bubbles narrow the
    /// way its filter chips do. A comma inside a term is escaped as `\,`, so
    /// a phrase like `New York\, NY` stays one term and survives the URL
    /// round-trip intact. See `split_q_terms`.
    q: Option<String>,
    /// Exact match on `audit_log.id`. Powers the `?event=<uuid>` deep-link
    /// — the dashboard fires this query to verify a deep-linked event exists
    /// and to render an anchor row when it falls outside the active filters.
    event_id: Option<Uuid>,
    /// Match a UUID across all relevant places: the row id, actor id,
    /// resource id, and the JSONB `detail` keys `execution_id` and
    /// `replayed_from_approval`. Powers the `uuid =` search bar key.
    uuid: Option<Uuid>,
    // ── Per-column `~` (contains) + `=` (match) filters driving the search
    // bar keys. `*_contains` are case-insensitive substrings (ILIKE).
    action_contains: Option<String>,
    resource_type_contains: Option<String>,
    description: Option<String>,
    description_contains: Option<String>,
    ip_address: Option<String>,
    ip_address_contains: Option<String>,
    /// Substring on the actor identity name (powers `agent ~` / `user ~` /
    /// `identity ~`), optionally scoped by `identity_kind`.
    identity_name_contains: Option<String>,
    /// Comma-separated identity kinds the actor must match (e.g. `user` or
    /// `agent,sub_agent`). Scopes the kind split for the `agent`/`user` keys.
    identity_kind: Option<String>,
    /// Owning user (root of the actor's chain): matches the user acting directly
    /// or any of their agents. Powers `user =` (the subtree-wide variant, vs the
    /// exact-actor `identity_id`).
    owner_user_id: Option<Uuid>,
    /// Substring on the owning user's name. Powers `user ~`.
    owner_user_contains: Option<String>,
    /// Upstream result of execution events (`detail.is_error`). `true` →
    /// executions whose upstream reported failure; `false` → executions
    /// that succeeded. Powers the `result =` search bar key.
    is_error: Option<bool>,
    /// Comma-separated metadata tags; a row must carry **all** of them
    /// (`service:metabase,sql:write` means "writes against Metabase"). Same
    /// comma convention as `identity_kind`. Powers the `tag =` search key.
    tag: Option<String>,
    /// Substring against any one tag — finds `table:warehouse/orders` without
    /// knowing the db label. Powers `tag ~`.
    tag_contains: Option<String>,
    /// Comma-separated risk values; a row must match **any** of them
    /// (`write,delete` means "anything mutating"). ORs where `tag` ANDs, since
    /// risk is one axis with mutually exclusive values. Powers the search bar's
    /// `risk =` and `risk !=` keys — `!=` arrives here as its complement.
    risk: Option<String>,
    /// Lowest risk to include on the `read < write < delete` ladder:
    /// `risk_min=write` is "write or worse". Expanded to a set and intersected
    /// with `risk` when both are given. Powers `risk >=`.
    risk_min: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    since: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    until: Option<OffsetDateTime>,
}

fn default_limit() -> i64 {
    50
}

fn deserialize_optional_datetime<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<OffsetDateTime>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = <Option<String>>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let dt = OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                .map_err(serde::de::Error::custom)?;
            Ok(Some(dt))
        }
    }
}

/// Split the `q` parameter into free-text terms on unescaped commas, so a
/// search phrase may itself contain one: `New York\, NY` is a single term.
///
/// `tag` and `identity_kind` split on a plain comma — they carry controlled
/// vocabularies where a comma cannot occur. `q` is arbitrary user text, and a
/// naive split would turn one search bubble into two on the next page load.
fn split_q_terms(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                // Only `,` and `\` are escapes; anything else keeps both
                // characters so a Windows path or a regex is never eaten.
                Some(next @ (',' | '\\')) => cur.push(next),
                Some(other) => {
                    cur.push('\\');
                    cur.push(other);
                }
                None => cur.push('\\'),
            },
            ',' => {
                let term = cur.trim();
                if !term.is_empty() {
                    out.push(term.to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let term = cur.trim();
    if !term.is_empty() {
        out.push(term.to_string());
    }
    out
}

/// Resolve `?risk=` and `?risk_min=` into the single set the repo filter takes.
///
/// `risk` is a comma-separated set (OR); `risk_min` is a rung on the
/// `read < write < delete` ladder, expanded upward by `Risk::at_least`. Given
/// both, the answer is their **intersection** — each parameter narrows, so
/// `risk=read,write&risk_min=write` means `write`.
///
/// Every value is parsed rather than passed through. An unrecognized one is a
/// 400: silently dropping it would widen the result set, and a filter that
/// quietly returns more than asked is the wrong failure mode for an audit log.
fn resolve_risks(
    risk: Option<String>,
    risk_min: Option<String>,
) -> std::result::Result<Option<Vec<String>>, AppError> {
    let parse_one = |s: &str| {
        Risk::parse(s.trim()).ok_or_else(|| {
            AppError::BadRequest(format!(
                "unknown risk `{}` — expected read, write or delete",
                s.trim()
            ))
        })
    };

    let explicit = match risk.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(
            raw.split(',')
                .filter(|v| !v.trim().is_empty())
                .map(parse_one)
                .collect::<std::result::Result<Vec<_>, _>>()?,
        ),
        None => None,
    };
    let floor = match risk_min.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(parse_one(raw)?.at_least()),
        None => None,
    };

    let resolved: Option<Vec<Risk>> = match (explicit, floor) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v),
        (Some(a), Some(b)) => Some(a.into_iter().filter(|r| b.contains(r)).collect()),
    };
    // An empty set is not "no filter" — it is a contradiction the caller
    // spelled out (`risk=read&risk_min=write`), and must return nothing rather
    // than everything. Kept as `Some(vec![])`, which `= ANY('{}')` satisfies
    // for no row.
    // Rendered back to the wire form the column stores. `Display` and
    // `Risk::parse` are inverses, so a value that survived parsing round-trips.
    Ok(resolved.map(|v| v.into_iter().map(|r| r.to_string()).collect()))
}

async fn query_audit(
    scope: OrgScope,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>> {
    let empty = |s: String| if s.is_empty() { None } else { Some(s) };
    let identity_kinds = params.identity_kind.and_then(empty).map(|s| {
        s.split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect::<Vec<_>>()
    });
    let q_terms = params.q.and_then(empty).map(|s| split_q_terms(&s));
    let tags = params.tag.and_then(empty).map(|s| {
        s.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
    });
    let risks = resolve_risks(params.risk, params.risk_min)?;
    let filter = AuditFilter {
        org_id: scope.org_id(),
        action: params.action,
        resource_type: params.resource_type,
        identity_id: params.identity_id,
        since: params.since,
        until: params.until,
        q_terms: q_terms.filter(|v| !v.is_empty()),
        event_id: params.event_id,
        uuid: params.uuid,
        action_contains: params.action_contains.and_then(empty),
        resource_type_contains: params.resource_type_contains.and_then(empty),
        description: params.description.and_then(empty),
        description_contains: params.description_contains.and_then(empty),
        ip_address: params.ip_address.and_then(empty),
        ip_address_contains: params.ip_address_contains.and_then(empty),
        identity_name_contains: params.identity_name_contains.and_then(empty),
        identity_kinds: identity_kinds.filter(|v| !v.is_empty()),
        owner_user_id: params.owner_user_id,
        owner_user_contains: params.owner_user_contains.and_then(empty),
        is_error: params.is_error,
        tags: tags.filter(|v| !v.is_empty()),
        tag_contains: params.tag_contains.and_then(empty),
        risks,
        limit: params.limit,
        before: params.before,
        before_id: params.before_id,
        offset: params.offset,
    };

    let rows = scope.query_audit_log(filter).await?;

    // The `approval.resolved` (and self-approve) event carries the resolver in
    // `detail.resolved_by_identity_id` — the row's `identity_id` is the
    // approval's *subject*. Pull the resolver id out so we enrich it alongside
    // the actor/impersonator below and render it distinctly in the dashboard.
    let resolved_by = |detail: &serde_json::Value| -> Option<Uuid> {
        detail
            .get("resolved_by_identity_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
    };

    // Batch-resolve identity names + kinds for actor, impersonator, and resolver.
    let all_ids: Vec<Uuid> = rows
        .iter()
        .flat_map(|r| {
            [
                r.identity_id,
                r.impersonated_by_identity_id,
                resolved_by(&r.detail),
            ]
        })
        .flatten()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let (name_map, kind_map): (HashMap<Uuid, String>, HashMap<Uuid, String>) = if all_ids.is_empty()
    {
        (HashMap::new(), HashMap::new())
    } else {
        let rows = scope
            .get_identity_names_by_ids(&all_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("failed to resolve identity names for audit response: {e}");
                Vec::new()
            });
        let mut names = HashMap::new();
        let mut kinds = HashMap::new();
        for (id, name, kind) in rows {
            names.insert(id, name);
            kinds.insert(id, kind);
        }
        (names, kinds)
    };

    // Resolve the SPIFFE path for each unique identity referenced on the page.
    // The page size is bounded (default 50) so per-id lookups are cheap; we
    // deduplicate to avoid repeating work when many rows share an actor.
    let mut path_map: HashMap<Uuid, (String, Vec<Uuid>)> = HashMap::new();
    for id in &all_ids {
        match crate::services::identity_path::build_for_identity(&scope, *id).await {
            Ok(Some(p)) => {
                path_map.insert(*id, p);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("failed to build identity_path for audit identity {id}: {e}");
            }
        }
    }

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                // Recorded name first (D56), live name only as a fallback for
                // rows predating migration 109. A hard-deleted identity keeps
                // its name here; the live map has nothing to offer for it.
                let identity_name = r
                    .actor_name
                    .or_else(|| r.identity_id.and_then(|id| name_map.get(&id).cloned()));
                let (identity_path, identity_path_ids) = r
                    .identity_id
                    .and_then(|id| path_map.get(&id).cloned())
                    .map(|(p, ids)| (Some(p), ids))
                    .unwrap_or((None, Vec::new()));
                let impersonated_by_name = r
                    .impersonated_by_identity_id
                    .and_then(|id| name_map.get(&id).cloned());
                let (impersonated_by_path, impersonated_by_path_ids) = r
                    .impersonated_by_identity_id
                    .and_then(|id| path_map.get(&id).cloned())
                    .map(|(p, ids)| (Some(p), ids))
                    .unwrap_or((None, Vec::new()));
                // Fall back to detail.description for pre-migration entries
                let description = r.description.or_else(|| {
                    r.detail
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                });
                // Enrich the resolver inline in `detail` (approval.resolved):
                // name/kind/path let the dashboard render the approver
                // distinctly from the subject. No-op for other events.
                let mut detail = r.detail;
                if let Some(rid) = resolved_by(&detail)
                    && let Some(obj) = detail.as_object_mut()
                {
                    if let Some(n) = name_map.get(&rid) {
                        obj.insert("resolved_by_name".into(), serde_json::json!(n));
                    }
                    if let Some(k) = kind_map.get(&rid) {
                        obj.insert("resolved_by_kind".into(), serde_json::json!(k));
                    }
                    if let Some((p, ids)) = path_map.get(&rid) {
                        obj.insert("resolved_by_path".into(), serde_json::json!(p));
                        obj.insert("resolved_by_path_ids".into(), serde_json::json!(ids));
                    }
                }
                AuditEntry {
                    id: r.id,
                    identity_id: r.identity_id,
                    identity_name,
                    owner_user_name: r.owner_user_name,
                    identity_path,
                    identity_path_ids,
                    action: r.action,
                    description,
                    resource_type: r.resource_type,
                    resource_id: r.resource_id,
                    detail,
                    ip_address: r.ip_address,
                    created_at: r.created_at,
                    impersonated_by_identity_id: r.impersonated_by_identity_id,
                    impersonated_by_name,
                    impersonated_by_path,
                    impersonated_by_path_ids,
                    tags: r.tags,
                    risk: r.risk,
                }
            })
            .collect(),
    ))
}
