//! Per-org admin step-up settings (`/v1/orgs/{id}/step-up-settings`).

use super::*;

#[derive(Serialize)]
pub(super) struct StepUpSettingsResponse {
    /// When `true`, an IdP sign-in whose ID token carries no `auth_time`
    /// counts its callback time for the admin step-up, instead of failing it
    /// with `auth_time_missing`. The step-up then proves a fresh round-trip
    /// through the IdP, not that the IdP re-checked a credential. Default
    /// `true`.
    accept_callback_time_without_auth_time: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatchStepUpSettingsRequest {
    accept_callback_time_without_auth_time: bool,
}

pub(super) async fn get_step_up_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<StepUpSettingsResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let value = overslash_db::repos::org::get_step_up_accept_callback_time(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(StepUpSettingsResponse {
        accept_callback_time_without_auth_time: value,
    }))
}

pub(super) async fn patch_step_up_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchStepUpSettingsRequest>,
) -> Result<Json<StepUpSettingsResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }
    let value = req.accept_callback_time_without_auth_time;
    let updated =
        overslash_db::repos::org::set_step_up_accept_callback_time(state.db(&ext), id, value)
            .await?;
    if !updated {
        return Err(AppError::NotFound("org not found".into()));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.step_up_settings.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({ "accept_callback_time_without_auth_time": value }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(StepUpSettingsResponse {
        accept_callback_time_without_auth_time: value,
    }))
}
