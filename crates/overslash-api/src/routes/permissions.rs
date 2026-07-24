use std::collections::{HashMap, HashSet};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_core::registry::ServiceRegistry;
use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, OrgAcl, ReqExt},
    services::principals::resolve_service_principals,
};

/// Build the service label a rule description leads with: the catalog display
/// name, plus the principal in parens when it is unambiguous ("GitHub" →
/// "GitHub (alice@acme.com)"). Returns `None` for a service the registry can't
/// name (org-custom templates, the `secret` pseudo-service), so those rules
/// fall back to the label-less sentence.
fn service_label(
    registry: &ServiceRegistry,
    principals: &HashMap<String, HashSet<String>>,
    action_pattern: &str,
) -> Option<String> {
    let slug = action_pattern.split(':').next().unwrap_or("");
    let base = registry.get(slug)?.display_name.clone();
    // Principal only when unambiguous: exactly one distinct account backs this
    // service for the rule's owner. Zero or several → name the service alone,
    // since a rule spans every account, not one.
    match principals.get(slug) {
        Some(set) if set.len() == 1 => {
            Some(format!("{base} ({})", set.iter().next().expect("len == 1")))
        }
        _ => Some(base),
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/permissions",
            post(create_permission).get(list_permissions),
        )
        .route(
            "/v1/permissions/{id}",
            delete(delete_permission).patch(update_permission),
        )
}

#[derive(Deserialize)]
struct CreatePermissionRequest {
    identity_id: Uuid,
    action_pattern: String,
    #[serde(default = "default_allow")]
    effect: String,
}

fn default_allow() -> String {
    "allow".into()
}

#[derive(Serialize)]
struct PermissionResponse {
    id: Uuid,
    identity_id: Uuid,
    action_pattern: String,
    /// The pattern as a sentence ("Send on any recipient at acme.com"), so a
    /// rule list reads without decoding key syntax. Rendered from the same
    /// `overslash-core` describer that writes an approval's suggested tiers.
    description: String,
    effect: String,
    expires_at: Option<String>,
    created_at: String,
}

async fn create_permission(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    let auth = acl;
    let row = scope
        .create_permission_rule(req.identity_id, &req.action_pattern, &req.effect, None)
        .await?;

    let _ = OrgScope::new(auth.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "permission_rule.created",
            resource_type: Some("permission_rule"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "identity_id": req.identity_id,
                "action_pattern": &row.action_pattern,
                "effect": &row.effect,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    // Resolve the principal for this rule's target identity so the returned
    // description leads with "GitHub (alice@acme.com) · …" when unambiguous.
    // Degrade to display-name-only on error — a label is a nicety, not a reason
    // to fail the create.
    let principals = resolve_service_principals(&scope, &state.registry, row.identity_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("principal resolution failed for permission create: {e}");
            HashMap::new()
        });
    let label = service_label(&state.registry, &principals, &row.action_pattern);

    Ok(Json(PermissionResponse {
        id: row.id,
        identity_id: row.identity_id,
        description: overslash_core::permissions::describe_pattern_named(
            &row.action_pattern,
            label.as_deref(),
        ),
        action_pattern: row.action_pattern,
        effect: row.effect,
        expires_at: row.expires_at.map(fmt_time),
        created_at: fmt_time(row.created_at),
    }))
}

#[derive(Deserialize)]
struct ListPermissionsQuery {
    identity_id: Option<Uuid>,
}

async fn list_permissions(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Query(q): Query<ListPermissionsQuery>,
) -> Result<Json<Vec<PermissionResponse>>> {
    // ?identity_id= is the identity-hierarchy detail panel filter: any
    // authenticated org member may list permission rules attached to a
    // specific identity in their own org. Cross-tenant ids are blocked at
    // the scope boundary (returns None).
    //
    // Without a query param the legacy MVP behaviour applies: list rules
    // for the calling identity.
    let identity_id = if let Some(target) = q.identity_id {
        scope
            .get_identity(target)
            .await?
            .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
        target
    } else {
        auth.identity_id
            .ok_or_else(|| AppError::BadRequest("no identity on this key".into()))?
    };
    let rows = scope
        .list_permission_rules_for_identity(identity_id)
        .await?;

    // One principal resolution for the whole list — the panel polls this every
    // 10 s, so it rides the call the page already makes. Degrade to
    // display-name-only labels if it fails; the rules still render.
    let principals = resolve_service_principals(&scope, &state.registry, identity_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("principal resolution failed for permission list: {e}");
            HashMap::new()
        });

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let label = service_label(&state.registry, &principals, &r.action_pattern);
                PermissionResponse {
                    id: r.id,
                    identity_id: r.identity_id,
                    description: overslash_core::permissions::describe_pattern_named(
                        &r.action_pattern,
                        label.as_deref(),
                    ),
                    action_pattern: r.action_pattern,
                    effect: r.effect,
                    expires_at: r.expires_at.map(fmt_time),
                    created_at: fmt_time(r.created_at),
                }
            })
            .collect(),
    ))
}

async fn delete_permission(
    acl: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    use overslash_core::permissions::AccessLevel;

    let rule = scope
        .get_permission_rule(id)
        .await?
        .ok_or_else(|| AppError::NotFound("permission rule not found".into()))?;

    // Allowed if (a) the caller owns this rule (self-service revoke from the
    // profile page) or (b) the caller has admin ACL on the org.
    let owns_it = acl
        .identity_id
        .map(|cid| cid == rule.identity_id)
        .unwrap_or(false);
    let is_admin = acl.access_level >= AccessLevel::Admin;
    if !owns_it && !is_admin {
        return Err(AppError::Forbidden(
            "cannot delete a permission rule you do not own".into(),
        ));
    }

    let deleted = scope.delete_permission_rule(id).await?;

    if deleted {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: acl.org_id,
                identity_id: acl.identity_id,
                action: "permission_rule.deleted",
                resource_type: Some("permission_rule"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

#[derive(Deserialize)]
struct UpdatePermissionRequest {
    /// Duration string (`"1h"`, `"24h"`, `"7d"`, `"30d"`). Absent, null, or
    /// `"forever"` clears the expiry (the rule becomes permanent). Interpreted
    /// as a *reset*: the new expiry is `now + ttl`, never an extension.
    #[serde(default)]
    ttl: Option<String>,
}

/// Parse a ttl string into an absolute expiry, mirroring the approval
/// "remember with ttl" flow: `now + ttl`, capped at 365 days. `None`/`"forever"`
/// clears the expiry.
fn ttl_to_expires_at(ttl: Option<&str>) -> Result<Option<OffsetDateTime>> {
    let Some(t) = ttl else { return Ok(None) };
    if t == "forever" {
        return Ok(None);
    }
    let dur = overslash_core::types::duration::parse_ttl(t)
        .ok_or_else(|| AppError::BadRequest(format!("invalid ttl: {t}")))?;
    if dur.as_secs() > 365 * 86400 {
        return Err(AppError::BadRequest("ttl must not exceed 365 days".into()));
    }
    let secs: i64 = dur
        .as_secs()
        .try_into()
        .map_err(|_| AppError::BadRequest("ttl value too large".into()))?;
    Ok(OffsetDateTime::now_utc().checked_add(time::Duration::new(secs, 0)))
}

async fn update_permission(
    State(state): State<AppState>,
    acl: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    use overslash_core::permissions::AccessLevel;

    let rule = scope
        .get_permission_rule(id)
        .await?
        .ok_or_else(|| AppError::NotFound("permission rule not found".into()))?;

    // Same gate as delete: the caller must own this rule (self-service from the
    // profile / their own Agents-view row) or hold admin ACL on the org.
    let owns_it = acl
        .identity_id
        .map(|cid| cid == rule.identity_id)
        .unwrap_or(false);
    let is_admin = acl.access_level >= AccessLevel::Admin;
    if !owns_it && !is_admin {
        return Err(AppError::Forbidden(
            "cannot edit a permission rule you do not own".into(),
        ));
    }

    let expires_at = ttl_to_expires_at(req.ttl.as_deref())?;

    let row = scope
        .update_permission_rule_expiry(id, expires_at)
        .await?
        .ok_or_else(|| AppError::NotFound("permission rule not found".into()))?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "permission_rule.updated",
            resource_type: Some("permission_rule"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "expires_at": row.expires_at.map(fmt_time),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    // Keep the edited row's description consistent with create/list: lead with
    // the service label (and principal when unambiguous), degrading on error.
    let principals = resolve_service_principals(&scope, &state.registry, row.identity_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("principal resolution failed for permission update: {e}");
            HashMap::new()
        });
    let label = service_label(&state.registry, &principals, &row.action_pattern);

    Ok(Json(PermissionResponse {
        id: row.id,
        identity_id: row.identity_id,
        description: overslash_core::permissions::describe_pattern_named(
            &row.action_pattern,
            label.as_deref(),
        ),
        action_pattern: row.action_pattern,
        effect: row.effect,
        expires_at: row.expires_at.map(fmt_time),
        created_at: fmt_time(row.created_at),
    }))
}
