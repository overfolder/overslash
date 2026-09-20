//! The credential-probe endpoints for a service instance: ask, and finish.
//!
//! Two verbs over one probe, kept apart on purpose. `/test` answers "are these
//! credentials good?" and writes nothing — the service detail page runs it
//! against live instances, and `require_owner_or_admin` admits an org *admin*
//! to instances they do not own, so a promoting `/test` would let an admin
//! sweeping the org silently publish other people's unverified drafts.
//! `/activate` is the write: the same probe, plus the promotion that makes a
//! `pending_setup` instance callable.
//!
//! Split out of `mod.rs` at that seam rather than for size alone: these two
//! are the only handlers in the file that reach into the action-call path,
//! which is why they carry eight and nine extractors between them.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use super::require_owner_or_admin;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp, OrgAcl, ReqExt, WriteAcl},
    routes::actions::probe,
    services::platform_services,
};

/// Run this instance's template-declared credential probe.
///
/// The endpoint exists so no caller has to know which action the probe is —
/// the template says (`x-overslash-test`) and this resolves it. The call
/// itself is ordinary: same permission chain, same approval gate. See
/// [`crate::routes::actions::probe`] for why that is not a bypass in the
/// case it was built for.
///
/// Gated by `require_owner_or_admin` rather than by execute access: pressing
/// this is a management act on the instance ("are its credentials good?"),
/// and the owner is who is being asked.
// Eight extractors: the probe delegates to `call_action_impl`, which needs
// the same six the `/v1/actions/call` handler does, plus this route's own
// path id and the ACL the ownership check reads.
#[allow(clippy::too_many_arguments)]
pub(super) async fn test_service(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    transport: crate::extractors::CallerTransport,
    Path(id): Path<Uuid>,
) -> Result<Json<probe::ServiceTestResponse>> {
    let instance = scope
        .get_service_instance(id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    require_owner_or_admin(&scope, &instance, &acl).await?;

    // Resolved as the instance's *owner*, not the caller. The user tier is
    // keyed on that identity, so resolving as an admin probing someone else's
    // instance would miss the user-tier template it is actually built from —
    // and a caller who happens to own a same-key template of their own would
    // shadow the instance's real one. Every other instance-view path passes
    // `owner_identity_id` for the same reason.
    let def = platform_services::resolve_template_definition(
        state.db(&ext),
        &state.registry,
        acl.org_id,
        instance.owner_identity_id,
        &instance.template_key,
    )
    .await?;

    let verdict = probe::run(
        state.clone(),
        ext,
        auth,
        scope,
        ip,
        transport,
        &instance,
        &def,
    )
    .await?;
    Ok(Json(verdict))
}

/// Query params for `POST /v1/services/{id}/activate`.
#[derive(Deserialize, Default)]
pub(super) struct ActivateQuery {
    /// Activate without a passing verdict — the dashboard's "Activate anyway".
    ///
    /// A query param rather than a body field to match `DeleteServiceQuery`
    /// below, and because this is a POST that otherwise carries nothing: an
    /// `Option<Json<T>>` on an empty body is a papercut every caller pays for.
    #[serde(default)]
    force: bool,
}

/// The answer to "is this instance live now, and what did the probe say?".
#[derive(Serialize)]
pub(super) struct ActivateServiceResponse {
    /// The instance's status *after* this call. `pending_setup` means the
    /// verdict did not clear it.
    status: String,
    /// `None` only when `force` skipped the probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<probe::ServiceTestResponse>,
}

/// Run the credential probe and, if it passes, make the instance callable.
///
/// The promoting half of [`test_service`], kept as a separate endpoint rather
/// than folded into it. `/test` is a diagnostic — the service detail page runs
/// it against already-live instances to ask "are these credentials still
/// good?" — and `require_owner_or_admin` admits an org **admin** to instances
/// they do not own. Promote-on-green inside `/test` would therefore mean an
/// admin sweeping the org's instances silently published other people's
/// unverified drafts. Making the write its own verb keeps "ask" and "publish"
/// separable, which is the same reason [`probe`] carries no response body.
///
/// Every outcome is a `200`. A red verdict is the answer to the question the
/// caller asked, not a failure to answer it — a 4xx here would make the
/// dashboard render an error where it should render a verdict and a retry.
// Nine extractors, for the same reason `test_service` has eight: it delegates
// to `call_action_impl`, which needs the six the `/v1/actions/call` handler
// does, plus this route's path id, the ACL the ownership check reads, and the
// `force` query.
#[allow(clippy::too_many_arguments)]
pub(super) async fn activate_service(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    transport: crate::extractors::CallerTransport,
    Path(id): Path<Uuid>,
    Query(q): Query<ActivateQuery>,
) -> Result<Json<ActivateServiceResponse>> {
    let instance = scope
        .get_service_instance(id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    require_owner_or_admin(&scope, &instance, &acl).await?;
    if instance.is_system {
        return Err(AppError::BadRequest("cannot modify system service".into()));
    }
    // Un-archiving is a deliberate act, and it belongs to `PATCH /status` where
    // the operator is choosing it. Letting a probe do it would mean a green
    // credential silently resurrected a service someone retired.
    if instance.status == "archived" {
        return Err(AppError::BadRequest(
            "cannot activate an archived service; restore it first".into(),
        ));
    }

    // Forced: do not run the probe at all. Burning an upstream call whose
    // answer is discarded would be dishonest about what was checked, and the
    // audit row below is what records that nothing was.
    if q.force {
        let status = promote(&state, &ext, &scope, &acl, &instance, None, true).await?;
        return Ok(Json(ActivateServiceResponse {
            status,
            verdict: None,
        }));
    }

    // Resolved as the instance's *owner* for the reason `test_service` states.
    let def = platform_services::resolve_template_definition(
        state.db(&ext),
        &state.registry,
        acl.org_id,
        instance.owner_identity_id,
        &instance.template_key,
    )
    .await?;

    let verdict = probe::run(
        state.clone(),
        ext.clone(),
        auth,
        scope.clone(),
        ip,
        transport,
        &instance,
        &def,
    )
    .await?;

    // `not_supported` promotes. A template can lose its `x-overslash-test`
    // after an instance was gated on it — an org template edit, a layer
    // dropped — and refusing forever over a probe that no longer exists would
    // strand the instance until the sweeper ate it. The audit row records
    // which verdict let it through.
    let passed = matches!(verdict.status, "ok" | "not_supported");
    let status = if passed {
        promote(&state, &ext, &scope, &acl, &instance, Some(&verdict), false).await?
    } else {
        instance.status.clone()
    };
    Ok(Json(ActivateServiceResponse {
        status,
        verdict: Some(verdict),
    }))
}

/// Flip an instance to `active`, audit it, and announce it.
///
/// Returns the resulting status. Idempotent on an instance that is already
/// active, so a client may always call activate and read the answer.
async fn promote(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    acl: &OrgAcl,
    instance: &overslash_db::repos::service_instance::ServiceInstanceRow,
    verdict: Option<&probe::ServiceTestResponse>,
    forced: bool,
) -> Result<String> {
    if instance.status == "active" {
        return Ok(instance.status.clone());
    }
    let row = scope
        .update_service_instance_status(instance.id, "active")
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;

    let detail = serde_json::json!({
        "from": instance.status,
        "to": "active",
        "forced": forced,
        // The verdict's four scalar fields, never its error text or a body:
        // an audit row is read by more people than pressed the button.
        "verdict": verdict.map(|v| serde_json::json!({
            "status": v.status,
            "http_status": v.http_status,
            "latency_ms": v.latency_ms,
        })),
    });
    let _ = scope
        .log_audit(overslash_db::repos::audit::AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "service.activated",
            resource_type: Some("service_instance"),
            resource_id: Some(row.id),
            detail: detail.clone(),
            description: None,
            ip_address: None,
        })
        .await;

    crate::services::events::emit(
        state.db_pool(ext),
        state.http_client.clone(),
        crate::services::events::EventDraft {
            org_id: acl.org_id,
            event_type: crate::services::events::EventType::ServiceActivated,
            payload: serde_json::json!({
                "service_id": row.id,
                "service_name": row.name,
                "template_key": row.template_key,
                "status": "active",
                "forced": forced,
                "verdict": detail.get("verdict").cloned(),
            }),
            audience: crate::services::events::audience::for_service_setup(
                scope,
                row.owner_identity_id,
                acl.identity_id,
                row.id,
            )
            .await,
        },
    );
    Ok(row.status)
}
