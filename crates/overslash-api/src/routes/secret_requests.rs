//! Standalone "Provide Secret" flow.
//!
//! Four endpoints:
//! - `POST /v1/secrets/requests` (authenticated): mint a request + signed URL.
//! - `GET  /public/secrets/provide/{req_id}?token=...`: render-time metadata.
//! - `POST /public/secrets/provide/{req_id}`: submit value, encrypt, store,
//!   and — when the request names a service — bind its credential slot.
//! - `GET  /public/services/setup/{req_id}?token=...`: the same metadata plus
//!   the service, for the setup page. Metadata only: that page submits to the
//!   POST above, because there is one write path.
//!
//! Public endpoints take no auth extractor — security comes from the JWT in
//! the URL plus a server-side `secret_requests` row that enforces single-use
//! and binds the token to a specific secret slot on a specific identity.
//!
//! See `SPEC.md` §5 / §11 and `docs/design/INDEX.md`.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::{audit::AuditEntry, secret_request};
use overslash_db::scopes::OrgScope;

use super::util::fmt_time;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, ReqExt, WriteAcl},
    services::jwt,
    services::service_setup::{self, sha256},
    services::session::extract_session,
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/secrets/requests", post(create_secret_request))
        .route(
            "/public/secrets/provide/{req_id}",
            get(get_provide).post(submit_provide),
        )
        // Metadata only. The setup page submits to the provide endpoint
        // above — the write path is identical, and duplicating it would put
        // the credential-binding step in two places.
        .route("/public/services/setup/{req_id}", get(get_setup))
}

// ─── 1. Mint (authenticated) ──────────────────────────────────────────

#[derive(Deserialize)]
struct CreateSecretRequestBody {
    secret_name: String,
    /// Identity that the secret belongs to / will be `created_by` for. Defaults
    /// to the caller's own identity if omitted.
    identity_id: Option<Uuid>,
    reason: Option<String>,
    /// Time-to-live for the URL, in seconds. Capped at 24h, defaults to 1h.
    ttl_seconds: Option<u64>,
    /// Service instance this value is for. When set, fulfilling the request
    /// also binds the instance's credential slot, and the minted URL points
    /// at the setup page rather than the bare provide page.
    service_id: Option<Uuid>,
    /// Which credential slot to bind. Optional when the template declares a
    /// single per-instance slot, which is every shipped template.
    credential_key: Option<String>,
}

#[derive(Serialize)]
struct CreateSecretRequestResponse {
    id: String,
    token: String,
    url: String,
    /// Best-effort short URL via the configured `oversla.sh` instance.
    /// `None` when the shortener isn't configured or the mint fails — the
    /// canonical `url` is always usable.
    #[serde(skip_serializing_if = "Option::is_none")]
    short_url: Option<String>,
    expires_at: String,
    /// Echoed back when the request was bound to a service instance, so a
    /// caller that omitted `credential_key` learns which slot was inferred.
    #[serde(skip_serializing_if = "Option::is_none")]
    service_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_key: Option<String>,
}

const DEFAULT_TTL: u64 = 3600;
const MAX_TTL: u64 = 86_400;

async fn create_secret_request(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Json(req): Json<CreateSecretRequestBody>,
) -> Result<Json<CreateSecretRequestResponse>> {
    if req.secret_name.trim().is_empty() {
        return Err(AppError::BadRequest("secret_name is required".into()));
    }

    let caller_identity = acl
        .identity_id
        .ok_or_else(|| AppError::Unauthorized("identity required".into()))?;
    let target_identity = req.identity_id.unwrap_or(caller_identity);

    // Verify the target identity belongs to the same org so a caller cannot
    // mint a request scoped to another tenant.
    let scope = OrgScope::new(acl.org_id, state.db_pool(&ext));
    let _target = scope
        .get_identity(target_identity)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    // Resolve the service binding, if any, before anything is written. This
    // is the only place the `(service_id, credential_key)` pair is checked —
    // fulfilment runs from a public route with no caller to re-check.
    let binding = match req.service_id {
        Some(service_id) => Some(
            service_setup::validate_binding(
                &scope,
                &state.registry,
                Some(caller_identity),
                acl.access_level,
                service_id,
                req.credential_key.as_deref(),
            )
            .await?,
        ),
        None => None,
    };

    let ttl = req.ttl_seconds.unwrap_or(DEFAULT_TTL).clamp(60, MAX_TTL) as i64;

    // Capture the org's User-Signed-Mode policy at *mint* time so flipping
    // the toggle later never retroactively breaks in-flight URLs. Default to
    // allowing unsigned if the org has no explicit setting (backwards
    // compat: existing orgs keep their current open behavior).
    let allow_unsigned =
        overslash_db::repos::org::get_allow_unsigned_secret_provide(state.db(&ext), acl.org_id)
            .await?
            .unwrap_or(true);
    let require_user_session = !allow_unsigned;

    let minted = service_setup::mint(
        state.db(&ext),
        &state.http_client,
        &state.config,
        service_setup::MintRequest {
            org_id: acl.org_id,
            target_identity,
            requested_by: caller_identity,
            secret_name: req.secret_name.trim(),
            reason: req.reason.as_deref(),
            ttl_seconds: ttl,
            require_user_session,
            service_instance_id: binding.as_ref().map(|(row, _)| row.id),
            credential_key: binding.as_ref().map(|(_, key)| key.as_str()),
            via: "rest",
            ip_address: ip.0.as_deref(),
        },
    )
    .await?;
    crate::services::events::emit(state.db_pool(&ext), state.http_client.clone(), minted.event);
    let (req_id, token, url, short_url, expires_at) = (
        minted.request_id,
        minted.token,
        minted.url,
        minted.short_url,
        minted.expires_at,
    );

    Ok(Json(CreateSecretRequestResponse {
        id: req_id,
        token,
        url,
        short_url,
        expires_at: fmt_time(expires_at),
        service_id: binding.as_ref().map(|(row, _)| row.id),
        credential_key: binding.map(|(_, key)| key),
    }))
}

// ─── 2. Public GET (page metadata) ────────────────────────────────────

#[derive(Deserialize)]
struct TokenQuery {
    token: String,
}

#[derive(Serialize)]
struct ProvideMetadata {
    id: String,
    secret_name: String,
    identity_label: String,
    requested_by_label: String,
    reason: Option<String>,
    expires_at: String,
    created_at: String,
    /// True iff the request was minted while the org had
    /// `allow_unsigned_secret_provide = false`. When set, the page must
    /// refuse to submit unless a same-org session is also present.
    require_user_session: bool,
    /// Populated iff the visitor carried a valid `oss_session` cookie for
    /// the same org as this request. Lets the page render a "Signed in as
    /// …" banner so the visitor knows their identity will be captured on
    /// the audit trail. Cross-tenant sessions are silently ignored.
    viewer: Option<ViewerInfo>,
}

#[derive(Serialize)]
struct ViewerInfo {
    identity_id: Uuid,
    email: String,
}

async fn get_provide(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Path(req_id): Path<String>,
    Query(q): Query<TokenQuery>,
) -> Result<Json<ProvideMetadata>> {
    let row = load_and_validate(&state, &ext, &req_id, &q.token).await?;
    let scope = OrgScope::new(row.org_id, state.db_pool(&ext));
    Ok(Json(provide_metadata(&state, &scope, &headers, row).await?))
}

/// Render the request-level half of a public page's metadata. Shared by the
/// bare provide page and the service setup page, which differ only in what
/// they wrap around it.
async fn provide_metadata(
    state: &AppState,
    scope: &OrgScope,
    headers: &HeaderMap,
    row: overslash_db::repos::secret_request::SecretRequestRow,
) -> Result<ProvideMetadata> {
    let identity_label = scope
        .get_identity(row.identity_id)
        .await?
        .map(|i| i.name)
        .unwrap_or_else(|| row.identity_id.to_string());
    let requested_by_label = scope
        .get_identity(row.requested_by)
        .await?
        .map(|i| i.name)
        .unwrap_or_else(|| row.requested_by.to_string());

    // Opportunistic session binding: if the visitor happens to already be
    // signed in to the same org, surface that so the page can show a banner.
    // Cross-tenant sessions are discarded — never echo identity from another
    // tenant on a public page.
    let viewer = extract_session(state, headers)
        .filter(|s| s.org == row.org_id)
        .map(|s| ViewerInfo {
            identity_id: s.sub,
            email: s.email,
        });

    Ok(ProvideMetadata {
        id: row.id,
        secret_name: row.secret_name,
        identity_label,
        requested_by_label,
        reason: row.reason,
        expires_at: fmt_time(row.expires_at),
        created_at: fmt_time(row.created_at),
        require_user_session: row.require_user_session,
        viewer,
    })
}

// ─── 2b. Public GET (service setup page metadata) ─────────────────────

/// What the standalone setup page renders.
///
/// A superset of [`ProvideMetadata`] rather than a separate shape: the page
/// still needs the countdown, the requester label and the user-signed-mode
/// gate, and the two pages are the same handshake wearing different clothes.
#[derive(Serialize)]
struct SetupMetadata {
    #[serde(flatten)]
    provide: ProvideMetadata,
    service: SetupService,
}

#[derive(Serialize)]
struct SetupService {
    id: Uuid,
    name: String,
    template_key: String,
    /// The template's display name — "Resend", not "resend".
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_url: Option<String>,
    /// The slot this link fills, with the label and help text the template
    /// authored for it.
    slot: SetupSlotView,
    /// Every per-instance slot on the template and whether it is already
    /// bound, so the page can say "1 of 2" honestly instead of implying this
    /// link finishes the job.
    slots: Vec<SetupSlotView>,
    /// The template's credential probe. Present means the page may offer a
    /// Test button — to a signed-in visitor, since the probe runs through the
    /// authenticated call path.
    #[serde(skip_serializing_if = "Option::is_none")]
    test_action: Option<crate::routes::actions::probe::TestActionRef>,
}

#[derive(Serialize, Clone)]
struct SetupSlotView {
    key: String,
    label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    /// True when the instance already has a secret bound to this slot.
    bound: bool,
}

async fn get_setup(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Path(req_id): Path<String>,
    Query(q): Query<TokenQuery>,
) -> Result<Json<SetupMetadata>> {
    let row = load_and_validate(&state, &ext, &req_id, &q.token).await?;

    // A request with no service binding belongs on `/secrets/provide`. Refuse
    // rather than render a service-shaped page around a missing service.
    let (Some(service_id), Some(credential_key)) =
        (row.service_instance_id, row.credential_key.clone())
    else {
        return Err(AppError::NotFound("not_found".into()));
    };

    let scope = OrgScope::new(row.org_id, state.db_pool(&ext));
    let instance = scope
        .get_service_instance(service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("not_found".into()))?;
    let def = crate::services::platform_services::resolve_template_definition(
        state.db(&ext),
        &state.registry,
        row.org_id,
        instance.owner_identity_id,
        &instance.template_key,
    )
    .await?;

    let (slot, slots) = slot_views(&def, &instance, &credential_key);

    let provide = provide_metadata(&state, &scope, &headers, row).await?;
    Ok(Json(SetupMetadata {
        provide,
        service: SetupService {
            id: instance.id,
            name: instance.name,
            template_key: instance.template_key,
            display_name: def.display_name.clone(),
            icon_url: crate::services::icon_url::resolve_icon_url(
                def.icon.as_ref(),
                &state.config.public_url,
            ),
            slot,
            slots,
            test_action: crate::routes::actions::probe::describe(&def),
        },
    }))
}

// ─── 3. Public POST (submit value) ────────────────────────────────────

#[derive(Deserialize)]
struct SubmitBody {
    token: String,
    value: String,
}

#[derive(Serialize)]
struct SubmitResponse {
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
struct SubmitServiceOutcome {
    id: Uuid,
    name: String,
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
}

async fn submit_provide(
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
        state.http_client.clone(),
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
                // The agent that minted a setup link is blocked on exactly
                // this: its service is now callable.
                "service_id": service.as_ref().map(|s| s.id),
                "service_name": service.as_ref().map(|s| s.name.as_str()),
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

/// Every per-instance slot of `def` with its bound state, plus the one this
/// link fills.
///
/// The named slot falls back to a view built from the key alone, which keeps
/// the page renderable if the template dropped the slot after the link was
/// minted — the binding still works, because the row names it.
fn slot_views(
    def: &overslash_core::types::ServiceDefinition,
    instance: &overslash_db::repos::service_instance::ServiceInstanceRow,
    credential_key: &str,
) -> (SetupSlotView, Vec<SetupSlotView>) {
    let slots: Vec<SetupSlotView> = crate::services::service_setup::instance_slots(def)
        .into_iter()
        .map(|s| SetupSlotView {
            bound: crate::services::service_setup::is_bound(&instance.credentials.0, &s.key),
            label: slot_label(&s),
            key: s.key,
            description: s.description,
        })
        .collect();
    let slot = slots
        .iter()
        .find(|s| s.key == credential_key)
        .cloned()
        .unwrap_or_else(|| SetupSlotView {
            label: humanize(credential_key),
            key: credential_key.to_string(),
            description: String::new(),
            bound: false,
        });
    (slot, slots)
}

/// A human-facing name for a credential slot.
///
/// The template's own `x-overslash-label` when it authored one, else the slot
/// key made readable (`api_key` → "API key"). The key is optional and most
/// shipped templates omit it — an implicit slot inherits the scheme's label,
/// which is empty — and the setup page *leads* with this string (it names the
/// field and completes the sentence "…needs its ___"), so an empty one is not
/// a missing nicety but a blank in the middle of a prompt.
///
/// Never the vault secret name:
/// that is an org-chosen identifier (`puppet_resend_key_1789…`), and reading
/// it back to the person pasting a value tells them nothing about what to
/// paste.
fn slot_label(slot: &overslash_core::types::SecretSlot) -> String {
    let authored = slot.label.trim();
    if !authored.is_empty() {
        return authored.to_string();
    }
    humanize(&slot.key)
}

/// `api_key` → "API key", `token` → "Token", `mailbox_pass` → "Mailbox pass".
///
/// Sentence case, not title case, and the only special rule is that a short
/// *leading* word is read as an acronym (`api_key`, `sql_dsn`). Restricting it
/// to the first word is what keeps "key" from becoming "KEY".
///
/// Deliberately tiny: the good answer is a template that authors a label, and
/// a cleverer transformation here would make the poor one look deliberate.
fn humanize(key: &str) -> String {
    let words: Vec<&str> = key.split(['_', '-']).filter(|w| !w.is_empty()).collect();
    let rendered: Vec<String> = words
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let acronym =
                i == 0 && words.len() > 1 && w.len() <= 3 && w.chars().all(|c| c.is_alphabetic());
            if acronym {
                w.to_uppercase()
            } else {
                w.to_lowercase()
            }
        })
        .collect();
    let out = rendered.join(" ");
    let mut chars = out.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => out,
    }
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
    let Some(instance) = scope
        .bind_credential_slot(service_id, credential_key, secret_name)
        .await?
    else {
        return Ok(None);
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
        name: instance.name,
        credential_key: credential_key.to_string(),
        remaining_slots,
    }))
}

// ─── helpers ──────────────────────────────────────────────────────────

/// Validate the JWT, look up the row, and check expiry / fulfillment / token
/// hash. Returns the row on success. All failures map to neutral, stable
/// codes — never echo internal detail to the public client.
async fn load_and_validate(
    state: &AppState,
    ext: &axum::http::Extensions,
    req_id: &str,
    token: &str,
) -> Result<overslash_db::repos::secret_request::SecretRequestRow> {
    let signing_key = jwt::signing_key_bytes(&state.config.signing_key);
    let claims = jwt::verify_secret_request(&signing_key, token)
        .map_err(|_| AppError::BadRequest("invalid_token".into()))?;
    if claims.req != req_id {
        return Err(AppError::BadRequest("invalid_token".into()));
    }

    let row = secret_request::get(state.db(ext), req_id)
        .await?
        .ok_or_else(|| AppError::NotFound("not_found".into()))?;

    if row.org_id != claims.org {
        return Err(AppError::BadRequest("invalid_token".into()));
    }
    // Constant-time-ish hash compare. token_hash is short and not secret-bearing,
    // but use a length-then-eq check anyway.
    let provided_hash = sha256(token);
    if provided_hash != row.token_hash {
        return Err(AppError::BadRequest("invalid_token".into()));
    }
    if row.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Gone("expired".into()));
    }
    if row.fulfilled_at.is_some() {
        return Err(AppError::Gone("already_fulfilled".into()));
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::humanize;

    #[test]
    fn humanize_makes_a_slot_key_readable() {
        assert_eq!(humanize("token"), "Token");
        assert_eq!(humanize("api_key"), "API key");
        assert_eq!(humanize("mailbox_pass"), "Mailbox pass");
        // A hyphenated key reads the same as an underscored one.
        assert_eq!(humanize("client-secret"), "Client secret");
    }

    /// A blank never reaches the page: the label completes a sentence there,
    /// so the fallback has to produce *something*.
    #[test]
    fn humanize_never_returns_empty_for_a_real_key() {
        for key in ["x", "a_b", "__token__"] {
            assert!(!humanize(key).is_empty(), "{key} humanized to nothing");
        }
    }
}
