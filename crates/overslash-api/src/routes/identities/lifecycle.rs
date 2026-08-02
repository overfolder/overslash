//! Identity lifecycle: cascade-archive a subtree and restore an archived
//! sub_agent.

use super::*;

#[derive(Serialize)]
pub(super) struct RestoreResponse {
    identity: IdentityResponse,
    api_keys_resurrected: u64,
}

pub(super) async fn restore_identity(
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<RestoreResponse>> {
    // Restore mints fresh state (un-archives identity, resurrects API keys),
    // so it requires write-level ACL on the overslash service — read-only
    // users must not be able to revive archived identities.
    //
    // Org-scope and kind checks happen here for clear error messages, but the
    // parent-archived guard runs INSIDE the repo transaction (with FOR UPDATE
    // row locks) to close the TOCTOU race against archive_idle_subagents.
    let existing = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if existing.kind != "sub_agent" {
        return Err(AppError::BadRequest(
            "only sub_agent identities can be restored".into(),
        ));
    }

    match scope.restore_identity(id).await? {
        RestoreOutcome::Restored {
            identity,
            api_keys_resurrected,
        } => {
            let _ = scope
                .log_audit(AuditEntry {
                    org_id: acl.org_id,
                    identity_id: acl.identity_id,
                    action: "identity.restored",
                    resource_type: Some("identity"),
                    resource_id: Some(identity.id),
                    detail: serde_json::json!({
                        "name": &identity.name,
                        "api_keys_resurrected": api_keys_resurrected,
                    }),
                    description: None,
                    ip_address: ip.0.as_deref(),
                })
                .await;
            Ok(Json(RestoreResponse {
                identity: (*identity).into(),
                api_keys_resurrected,
            }))
        }
        RestoreOutcome::NotArchived => Err(AppError::BadRequest("identity is not archived".into())),
        RestoreOutcome::PastRetention => Err(AppError::Conflict(
            "identity is past its retention window and cannot be restored".into(),
        )),
        RestoreOutcome::ParentArchived => Err(AppError::Conflict(
            "cannot restore identity while parent is archived; restore the parent first".into(),
        )),
        RestoreOutcome::NotFound => Err(AppError::NotFound("identity not found".into())),
    }
}

#[derive(Deserialize, Default)]
pub(super) struct ArchiveRequest {
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
pub(super) struct ArchiveResponse {
    identity: IdentityResponse,
    archived_count: u64,
}

/// Cascade-archive an identity and its descendant subtree.
///
/// Unlike restore (sub_agent-only), this accepts any kind — overfolder archives
/// user identities too (e.g. on ghost-merge/delete). Archiving revokes API keys
/// and expires pending approvals for everything in the subtree, so it requires
/// write-level ACL. Idempotent: re-archiving an already-archived root returns
/// 200 with `archived_count: 0`. The optional JSON body `{ "reason": "..." }`
/// may be omitted (defaults to `"manual"`).
pub(super) async fn archive_identity(
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    body: Option<Json<ArchiveRequest>>,
) -> Result<Json<ArchiveResponse>> {
    // Existence + org-scope check up front for a clean 404 (cross-tenant ids
    // return None). The repo also returns None for a missing root.
    let _existing = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let req = body.map(|Json(b)| b).unwrap_or_default();
    let reason = req.reason.as_deref().or(Some(ARCHIVED_REASON_MANUAL));

    let outcome = scope
        .archive_identity(id, reason)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "identity.archived",
            resource_type: Some("identity"),
            resource_id: Some(outcome.identity.id),
            detail: serde_json::json!({
                "name": &outcome.identity.name,
                "kind": &outcome.identity.kind,
                "archived_count": outcome.archived_count,
                "reason": outcome.identity.archived_reason,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(ArchiveResponse {
        identity: (*outcome.identity).into(),
        archived_count: outcome.archived_count,
    }))
}
