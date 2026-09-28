//! The public write path of a secret request: submitting the value (and, for
//! a setup link, binding it to its service slot), or declining.

use super::*;

// ─── 3. Public POST (submit value) ────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct SubmitBody {
    token: String,
    value: String,
}

#[derive(Serialize)]
pub(super) struct SubmitResponse {
    ok: bool,
    name: String,
    version: i32,
    /// Present when this request was bound to a service instance. Lets the
    /// setup page decide what to render next without a second round-trip:
    /// run the test action, or name the slots still outstanding.
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<SubmitServiceOutcome>,
}

#[derive(Serialize)]
pub(super) struct SubmitServiceOutcome {
    id: Uuid,
    /// Absent when the bind failed — the name is read off the row the bind
    /// returns, and there is no row to read.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// Whether the credential is actually attached to the instance.
    ///
    /// `false` means the secret is safely in the vault but the binding did
    /// not land, so the service is *not* callable and somebody has to finish
    /// it from the dashboard. Explicit rather than inferred from an absent
    /// field: every consumer of this block branches on "is it ready", and
    /// letting a failed bind look like a plain secret request would have the
    /// page announce success over an instance that still cannot be called.
    bound: bool,
    /// The slot this submission just bound.
    credential_key: String,
    /// Credential slots this instance still needs a value for. Empty means it
    /// is fully provisioned, which is when the page can offer the test.
    ///
    /// Absent — not empty — when the template would not resolve, because "not
    /// known" and "none left" are different answers and only one of them means
    /// the service is ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_slots: Option<Vec<String>>,
    /// The instance's lifecycle status *after* this submission.
    ///
    /// `remaining_slots: []` used to mean "callable". Since D86 it means
    /// "every credential is present", which is a different and earlier claim:
    /// an instance created by a setup flow sits in `pending_setup` until its
    /// probe comes back green, and this handler runs *before* the probe — the
    /// page runs it, with the visitor's session. So the page and the waiting
    /// agent both need this field to tell "saved" from "live".
    ///
    /// Absent when the bind failed, for the same reason `name` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

pub(super) async fn submit_provide(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    ip: ClientIp,
    Path(req_id): Path<String>,
    Json(body): Json<SubmitBody>,
) -> Result<Json<SubmitResponse>> {
    if body.value.is_empty() {
        return Err(AppError::BadRequest("value is required".into()));
    }
    let row = load_and_validate(&state, &ext, &req_id, &body.token).await?;

    // Resolve any same-org session cookie the visitor happens to carry.
    // Cross-tenant sessions are discarded (treated as anonymous). We do NOT
    // trust a session alone — the URL JWT is always the capability gate. The
    // session is purely an identity attestation layered on top.
    let session = extract_session(&state, &headers).filter(|s| s.org == row.org_id);

    // Policy gate: if the row was minted under User-Signed-Mode-required,
    // a same-org session is mandatory. This is the only path by which the
    // public endpoint rejects an otherwise-valid JWT.
    if row.require_user_session && session.is_none() {
        return Err(AppError::Unauthorized("user_session_required".into()));
    }

    let provisioned_by_user_id = session.as_ref().map(|s| s.sub);

    // Single-use guard *before* writing to the vault. If a parallel request
    // already fulfilled this row, abort. Done *after* the policy check so a
    // rejected submission does not burn the request.
    if !secret_request::mark_fulfilled(state.db(&ext), &req_id).await? {
        return Err(AppError::Gone("already_fulfilled".into()));
    }

    // Mirrors routes/secrets.rs::put_secret encryption + storage path.
    let enc_key = state.config.keyring()?;
    let encrypted = crypto::encrypt(&enc_key, body.value.as_bytes())?;

    let scope = OrgScope::new(row.org_id, state.db_pool(&ext));
    // The target identity captured at request-creation time owns the slot
    // (visibility) and is also the version's `created_by` (attribution).
    // The slot's `owner_identity_id` is set on first insert and preserved
    // by repo `put`'s COALESCE on subsequent versions.
    let (stored, _ver) = scope
        .put_secret(
            &row.secret_name,
            &encrypted,
            Some(row.identity_id),
            Some(row.identity_id),
            provisioned_by_user_id,
        )
        .await?;

    // Bind the credential slot when this was a setup request. Ordered after
    // the vault write so a failure here cannot leave an instance pointing at
    // a secret that does not exist; the reverse — a stored secret with no
    // binding — is recoverable from the dashboard, and the request row is
    // already burned either way.
    let service = bind_setup_slot(
        &state,
        &ext,
        &scope,
        &row,
        &stored.name,
        provisioned_by_user_id,
        ip.0.as_deref(),
    )
    .await?;

    // When a session is present, attribute the audit entry to the human who
    // pasted the value. Otherwise fall back to the target identity (the one
    // that owns the secret slot) to keep the audit row anchored to *some*
    // identity for compliance queries.
    let audit_identity = provisioned_by_user_id.or(Some(row.identity_id));
    let _ = scope
        .log_audit(AuditEntry {
            org_id: row.org_id,
            identity_id: audit_identity,
            action: "secret_request.fulfilled",
            resource_type: Some("secret_request"),
            resource_id: None,
            detail: serde_json::json!({
                "id": &row.id,
                "name": &stored.name,
                "version": stored.current_version,
                "provisioned_by_user_id": provisioned_by_user_id,
                "user_signed": provisioned_by_user_id.is_some(),
                "require_user_session": row.require_user_session,
                "service_instance_id": row.service_instance_id,
                "credential_key": row.credential_key.as_deref(),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    // This is the event an agent blocked on a missing credential is waiting
    // for. It is emitted from a public, unauthenticated route, so the audience
    // comes entirely from the request row rather than from a caller identity —
    // whoever pasted the value is not, by that act, entitled to the stream.
    let audience = crate::services::events::audience::for_secret_request(
        &scope,
        row.requested_by,
        row.identity_id,
    )
    .await;
    crate::services::events::emit(
        state.db_pool(&ext),
        crate::services::events::EventDraft {
            org_id: row.org_id,
            event_type: crate::services::events::EventType::SecretRequestFulfilled,
            payload: serde_json::json!({
                "request_id": &row.id,
                "secret_name": &stored.name,
                "version": stored.current_version,
                "identity_id": row.identity_id,
                "requested_by": row.requested_by,
                "provisioned_by_user_id": provisioned_by_user_id,
                "user_signed": provisioned_by_user_id.is_some(),
                // The agent that minted a setup link is blocked on the moment
                // its service becomes callable — which since D86 is *not*
                // this moment. The credential has landed; the probe has not
                // run. `service_status` says which, and `service.activated`
                // is the event that reports the other.
                "service_id": service.as_ref().map(|s| s.id),
                "service_status": service.as_ref().and_then(|s| s.status.clone()),
                "service_name": service.as_ref().and_then(|s| s.name.as_deref()),
                "credential_bound": service.as_ref().map(|s| s.bound),
                "credential_key": service.as_ref().map(|s| s.credential_key.as_str()),
                "remaining_slots": service.as_ref().and_then(|s| s.remaining_slots.clone()),
            }),
            audience,
        },
    );

    Ok(Json(SubmitResponse {
        ok: true,
        name: stored.name,
        version: stored.current_version,
        service,
    }))
}

/// Bind the credential slot a *setup* request names, once its value is in the
/// vault.
///
/// `None` for a plain secret request, which names no service, and for the
/// narrow case where the bind itself finds no row: the value is stored under
/// its own name and the request is spent, so the honest answer is to say
/// nothing about a service rather than invent one. (Deletion is *not* that
/// case — `service_instance_id` cascades, so a deleted instance takes the
/// request row with it and `load_and_validate` 404s long before here.)
///
/// Nothing is re-derived here. The slot key was validated against the template
/// at *mint* time by a caller holding `manage_services_own`; this route
/// carries a capability token and no identity to check one against.
async fn bind_setup_slot(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    row: &overslash_db::repos::secret_request::SecretRequestRow,
    secret_name: &str,
    provisioned_by_user_id: Option<Uuid>,
    ip: Option<&str>,
) -> Result<Option<SubmitServiceOutcome>> {
    let (Some(service_id), Some(credential_key)) =
        (row.service_instance_id, row.credential_key.as_deref())
    else {
        return Ok(None);
    };
    let instance = match scope
        .bind_credential_slot(service_id, credential_key, secret_name)
        .await
    {
        Ok(Some(instance)) => instance,
        // The row is not there. Nothing to bind and nothing to say about a
        // service, so this reads as a plain secret request.
        Ok(None) => return Ok(None),
        // Everything above this point is already committed — the request row
        // is burned, the vault version written — so propagating would answer
        // "Submission failed. Please try again." over a link whose retry says
        // `410 already_fulfilled`, and the value would look lost when it is
        // not. Report the truth instead: saved, not attached. `bound: false`
        // is what stops the page claiming the service is ready and what keeps
        // the waiting agent from calling it.
        Err(e) => {
            tracing::error!(
                service_instance_id = %service_id,
                credential_key,
                secret_name,
                error = %e,
                "secret stored but its credential slot could not be bound"
            );
            return Ok(Some(SubmitServiceOutcome {
                id: service_id,
                name: None,
                bound: false,
                credential_key: credential_key.to_string(),
                remaining_slots: None,
                status: None,
            }));
        }
    };

    let _ = scope
        .log_audit(AuditEntry {
            org_id: row.org_id,
            identity_id: provisioned_by_user_id.or(Some(row.identity_id)),
            action: "service.credential_bound",
            resource_type: Some("service_instance"),
            resource_id: Some(service_id),
            detail: serde_json::json!({
                "request_id": &row.id,
                "credential_key": credential_key,
                "secret_name": secret_name,
            }),
            description: None,
            ip_address: ip,
        })
        .await;

    // Which slots are still *unbound*, not which still have an outstanding
    // link. They are not the same question: a sibling link can expire, or the
    // slots can be filled one at a time via `request_secret`, and counting
    // requests would then report "done" over a half-bound instance — which is
    // what the page reads to say "connected" and what tells a waiting agent
    // the service is callable. Same source the page's pre-submit half reads
    // (`slots[].bound`), so the two halves cannot disagree.
    //
    // Degraded, never propagated. Everything above this point is already
    // committed — the row is burned, the vault version written, the slot
    // bound — so a failed template lookup (a deleted layer, key drift, a DB
    // blip) must not turn a succeeded submit into "Submission failed. Please
    // try again." over a link whose retry answers `410 already_fulfilled`.
    // `None` means "not known", which the page and the event both render as
    // silence rather than as completion.
    let remaining_slots = match crate::services::platform_services::resolve_template_definition(
        state.db(ext),
        &state.registry,
        row.org_id,
        instance.owner_identity_id,
        &instance.template_key,
    )
    .await
    {
        Ok(template) => Some(
            crate::services::service_setup::unprovisioned_instance_slots(
                &template,
                instance.auth_mode.as_deref(),
                &instance.credentials.0,
                instance.secret_name.as_deref(),
            ),
        ),
        Err(e) => {
            tracing::warn!(
                service_instance_id = %service_id,
                template_key = %instance.template_key,
                error = %e,
                "credential bound, but the template would not resolve to report remaining slots"
            );
            None
        }
    };

    Ok(Some(SubmitServiceOutcome {
        id: service_id,
        name: Some(instance.name),
        bound: true,
        credential_key: credential_key.to_string(),
        remaining_slots,
        status: Some(instance.status),
    }))
}

#[derive(Deserialize)]
pub(super) struct DeclineBody {
    token: String,
}

/// The page's Deny button. Records the refusal so a tool call waiting on
/// this link as a URL-mode elicitation ends now instead of timing out. Same
/// capability as a submission — the URL's signed token — and advisory only:
/// the request stays open, and a later submission still fulfils it.
pub(super) async fn decline_provide(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Path(req_id): Path<String>,
    Json(body): Json<DeclineBody>,
) -> Result<StatusCode> {
    load_and_validate(&state, &ext, &req_id, &body.token).await?;
    secret_request::mark_declined(state.db(&ext), &req_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed bind is reported, not hidden and not raised.
    ///
    /// By the time the bind runs, `mark_fulfilled` has burned the row and the
    /// vault version is written. Propagating would answer "Submission failed"
    /// over a link whose retry says `410 already_fulfilled`; returning no
    /// `service` block at all would look like a plain secret request and let
    /// the page announce the service is connected. `bound: false` is the only
    /// shape that says what actually happened.
    #[test]
    fn a_failed_bind_serializes_as_saved_but_unattached() {
        let outcome = SubmitServiceOutcome {
            id: Uuid::nil(),
            name: None,
            bound: false,
            credential_key: "token".into(),
            remaining_slots: None,
            status: None,
        };
        let v = serde_json::to_value(&outcome).unwrap();
        assert_eq!(v["bound"], false);
        assert_eq!(v["credential_key"], "token");
        assert!(
            v.get("name").is_none(),
            "no row came back, so there is no name to report: {v}"
        );
        assert!(
            v.get("remaining_slots").is_none(),
            "absent, not empty — empty would read as fully provisioned: {v}"
        );
    }

    /// The success shape, for contrast: the page reads `bound` and
    /// `remaining_slots` together to decide whether to offer the test.
    #[test]
    fn a_successful_bind_reports_what_remains() {
        let outcome = SubmitServiceOutcome {
            id: Uuid::nil(),
            name: Some("resend-work".into()),
            bound: true,
            credential_key: "token".into(),
            remaining_slots: Some(Vec::new()),
            status: Some("pending_setup".into()),
        };
        let v = serde_json::to_value(&outcome).unwrap();
        assert_eq!(v["bound"], true);
        assert_eq!(v["name"], "resend-work");
        assert_eq!(v["remaining_slots"], serde_json::json!([]));
        // Every slot filled is not the same claim as callable. The probe runs
        // after this handler returns, so a page that read `remaining_slots:
        // []` alone would announce a service live one round trip early.
        assert_eq!(v["status"], "pending_setup");
    }
}
