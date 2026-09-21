//! Service setup links: the one URL an agent hands its user to finish
//! standing up a service.
//!
//! A `secret_requests` row that names a `service_instance_id` and a
//! `credential_key` is a *setup* request rather than a bare secret request.
//! Fulfilling it writes the value into the vault **and** binds the named
//! credential slot on the instance, so the instance goes from
//! credential-less to callable in a single POST from the browser.
//!
//! This module owns the three things all the mint paths share — the URL
//! shape, the JWT-and-row handshake, and the "which slots still need a
//! value" question — so the REST endpoint (`POST /v1/secrets/requests`), the
//! MCP kernel (`overslash.request_secret`) and the auto-mint inside
//! `kernel_create_service` cannot drift apart.
//!
//! The OAuth half of setup has no equivalent here on purpose: it is already
//! carried end to end by `oauth_flows` + `service_instances.connection_id`,
//! and `kernel_create_service` surfaces it as the `connect` bundle this
//! module's `setup` bundle is modelled on.

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use overslash_core::types::SecretSlot;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::secret_request;
use overslash_db::scopes::OrgScope;

use crate::config::Config;
use crate::error::AppError;
use crate::services::jwt::{self, SECRET_REQUEST_KIND, SecretRequestClaims};
use crate::services::short_url;

mod conflicts;
mod slots;

pub use slots::{
    instance_slots, is_bound, unbound_instance_slots, unprovisioned_instance_slots,
    validate_binding,
};

pub use conflicts::{
    conflict_error_for_create, conflict_error_for_request, conflicting_secret_names,
};

/// Dashboard route the minted URL points at when the request names a service.
const SETUP_PATH: &str = "/services/setup";
/// …and when it does not: a bare secret request keeps the service-less page.
const PROVIDE_PATH: &str = "/secrets/provide";

/// TTL for an auto-minted setup link.
///
/// One hour, matching the MCP `request_secret` default. A setup link is handed
/// straight to a human who is expected to act on it now; a longer window
/// mostly means more live bearer URLs sitting in chat transcripts. A caller
/// who needs longer mints its own via `POST /v1/secrets/requests`, which takes
/// `ttl_seconds`.
const SETUP_LINK_TTL_SECS: i64 = 3600;

/// Ceiling on a caller-supplied setup-link TTL.
///
/// Lives here rather than beside the `POST /v1/secrets/requests` handler that
/// clamps to it, because it is the deadline the setup-draft sweeper is derived
/// from: an unverified instance must outlive every link that could still
/// fulfil it, or the sweeper deletes the instance out from under a human
/// mid-paste and cascades their live link with it. See
/// `Config::setup_draft_retention_secs`.
pub const MAX_LINK_TTL_SECS: i64 = 86_400;

// ── Bundle returned to the minting caller ────────────────────────────────

/// The setup links minted alongside a freshly-created service instance.
///
/// The secret-path twin of [`ConnectBundle`](crate::services::platform_services::ConnectBundle),
/// and shaped like it deliberately: an agent that already knows to hand
/// `connect.auth_url` to its user needs no new rule to hand over
/// `setup.setup_url`.
#[derive(Serialize, Debug)]
pub struct SetupBundle {
    /// The URL to hand the user. The first entry of `requests`; present as a
    /// scalar because that is what a caller does with this bundle, and no
    /// shipped template declares more than one instance-source slot.
    pub setup_url: String,
    /// Best-effort shortened form of `setup_url`. `None` when the shortener
    /// is unconfigured or the mint fails — `setup_url` is always usable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_url: Option<String>,
    /// One entry per credential slot still needing a value, each with its own
    /// single-use URL. A template with two unbound slots yields two links,
    /// handed over in sequence.
    pub requests: Vec<SetupRequestRef>,
    pub expires_at: String,
    /// Non-blocking notices about what these links will do when opened.
    ///
    /// Populated only on a `force: true` create, where every entry names a
    /// secret whose current value the link is about to supersede. Empty on the
    /// ordinary path, and omitted from the wire when empty — a caller that
    /// never forces never sees the field.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<SetupWarning>,
}

/// A non-blocking notice on a [`SetupBundle`].
///
/// Coded rather than prose-only, matching the template surface's
/// `ValidationIssue` / `ImportWarning`: the message is for a human reading a
/// dashboard, the `code` is what an agent or a test can branch on.
#[derive(Serialize, Debug)]
pub struct SetupWarning {
    /// `"overwrites_existing_secret"` is the only code today.
    pub code: &'static str,
    pub credential_key: String,
    pub secret_name: String,
    /// Version that a fulfilment of this link will supersede.
    pub current_version: i32,
    pub message: String,
}

#[derive(Serialize, Debug)]
pub struct SetupRequestRef {
    pub request_id: String,
    /// The template securityScheme slot key this link fills.
    pub credential_key: String,
    /// The vault name the value will be stored under.
    pub secret_name: String,
    pub setup_url: String,
    /// Best-effort shortened form of this entry's `setup_url`.
    ///
    /// Per entry, not just on the bundle: every link here is handed to a
    /// person separately, so every link wants the form that survives being
    /// pasted into a chat message. The bundle's own `short_url` is the first
    /// entry's, for the common single-slot case where a caller reads the
    /// scalar and never looks at `requests`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_url: Option<String>,
}

/// One minted request, as the mint helper returns it.
pub struct MintedRequest {
    pub request_id: String,
    /// The signed JWT. A bearer capability: never logged, never put on an
    /// event payload, and returned only to the caller that minted it.
    pub token: String,
    pub url: String,
    pub short_url: Option<String>,
    pub expires_at: time::OffsetDateTime,
    /// The `secret_request.created` event to publish.
    ///
    /// Returned rather than emitted so a caller minting several can publish
    /// them with one `emit_all` — two `emit` calls each spawn their own task
    /// and the inserts race, which would deliver a two-slot bundle's events
    /// out of authoring order.
    pub event: crate::services::events::EventDraft,
}

/// What a mint needs to know that is not derivable from the config.
pub struct MintRequest<'a> {
    pub org_id: Uuid,
    /// Identity the secret is stored under, and whose slot it fills.
    pub target_identity: Uuid,
    pub requested_by: Uuid,
    pub secret_name: &'a str,
    pub reason: Option<&'a str>,
    pub ttl_seconds: i64,
    /// The org's `allow_unsigned_secret_provide` policy, inverted. A *floor*,
    /// not the final value: [`mint`] raises it unconditionally when
    /// `service_instance_id` is set, because an anonymous fulfilment cannot
    /// produce the probe verdict such a request exists to trigger.
    pub require_user_session: bool,
    /// Both `Some` or both `None` — the DB check constraint says so, and
    /// [`validate_binding`] is what establishes it for a caller-supplied pair.
    pub service_instance_id: Option<Uuid>,
    pub credential_key: Option<&'a str>,
    /// Mint even though `secret_name` already names a live vault secret,
    /// accepting that fulfilment will store a new version over it.
    ///
    /// `false` is the safe default and refuses with
    /// [`AppError::SecretNameConflict`]. There is no third state: a caller
    /// either knows it is replacing a credential or it does not, and the
    /// whole point of the check is that "did not know" used to be silent.
    pub force: bool,
    /// Which surface minted this, for the audit row and the event payload:
    /// `"rest"`, `"mcp"` or `"create_service"`.
    pub via: &'static str,
    /// Caller IP for the audit row. `None` on paths that have none.
    pub ip_address: Option<&'a str>,
}

// ── Mint ──────────────────────────────────────────────────────────────────

/// Mint a signed, single-use provide URL and persist its `secret_requests` row.
///
/// The URL's *path* is the one thing that varies with `service_instance_id`:
/// a setup request lands on the page that leads with the service, a bare
/// secret request on the page that leads with the secret name. Both pages
/// submit to the same endpoint, so this is presentation, not a second
/// protocol.
pub async fn mint(
    db: &sqlx::PgPool,
    http_client: &reqwest::Client,
    config: &Config,
    req: MintRequest<'_>,
) -> Result<MintedRequest, AppError> {
    let scope = OrgScope::new(req.org_id, db.clone());

    // The backstop. Every surface that mints also checks earlier — the REST
    // and MCP kernels so the 409 carries their own wording, `create_service`
    // so it fails before writing the instance row — but the check lives here
    // too because this is the only function all three go through, and a
    // fourth caller must not be able to reintroduce the silent overwrite by
    // forgetting it.
    if !req.force {
        let conflicts = conflicting_secret_names(
            &scope,
            &[(
                req.credential_key.map(str::to_string),
                req.secret_name.to_string(),
            )],
        )
        .await?;
        if !conflicts.is_empty() {
            // Keyed on the *surface*, not on whether a slot is named. A REST
            // or MCP caller that passed `service_id` also has a
            // `credential_key`, and pointing that caller at
            // `credentials: {…}` would name a field its own request body does
            // not have — a fix it cannot apply.
            return Err(if req.via == "create_service" {
                conflict_error_for_create(conflicts)
            } else {
                conflict_error_for_request(conflicts, req.service_instance_id)
            });
        }
    }

    let now = time::OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(req.ttl_seconds);
    let request_id = format!("req_{}", Uuid::new_v4().simple());

    // A *setup* request always requires a session, whatever the org's
    // `allow_unsigned_secret_provide` says. One-directional: this can only
    // tighten the org's policy, never loosen it.
    //
    // Not a new policy so much as the page declining a submission it could not
    // complete. Fulfilling a setup request binds a credential slot *and* is the
    // trigger for the instance's probe — and the probe runs through
    // `call_action_impl`, which needs an identity to evaluate a permission
    // chain against. An anonymous fulfilment can therefore never produce a
    // verdict, so it would leave the instance in `pending_setup` until the
    // sweeper deleted it: the credential accepted, the service never live, and
    // nobody told why. `allow_unsigned` was written for the bare provide page,
    // where the only outcome is a stored value.
    //
    // Here rather than at the three call sites because that is this module's
    // whole job — see the module doc — and because those call sites have
    // already drifted apart once, over TTLs.
    let require_user_session = req.require_user_session || req.service_instance_id.is_some();

    let signing_key = jwt::signing_key_bytes(&config.signing_key);
    let claims = SecretRequestClaims {
        req: request_id.clone(),
        org: req.org_id,
        iat: now.unix_timestamp(),
        exp: expires_at.unix_timestamp(),
        kind: SECRET_REQUEST_KIND.into(),
    };
    let token = jwt::mint_secret_request(&signing_key, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint: {e}")))?;

    secret_request::create(
        db,
        &request_id,
        req.org_id,
        req.target_identity,
        req.secret_name,
        req.requested_by,
        req.reason,
        &sha256(&token),
        expires_at,
        require_user_session,
        req.service_instance_id,
        req.credential_key,
    )
    .await?;

    let path = if req.service_instance_id.is_some() {
        SETUP_PATH
    } else {
        PROVIDE_PATH
    };
    let url = config.dashboard_url_for(&format!("{path}/{request_id}?token={token}"));
    let short_url = short_url::mint_with_config(
        http_client,
        config.oversla_sh_base_url.as_deref(),
        config.oversla_sh_api_key.as_deref(),
        &url,
        expires_at,
    )
    .await;

    // Audited here rather than at each call site: the three mint paths had
    // three copies of this block and had already drifted, so one
    // `EventType::SecretRequestCreated` was shipping three payload shapes.
    //
    // Deliberately no token, `url` or `short_url` on either: those are bearer
    // capabilities, and anyone in the audience could otherwise fulfil the
    // request themselves.
    let _ = scope
        .log_audit(AuditEntry {
            org_id: req.org_id,
            identity_id: Some(req.requested_by),
            action: "secret_request.created",
            resource_type: Some("secret_request"),
            resource_id: None,
            detail: serde_json::json!({
                "id": &request_id,
                "secret_name": req.secret_name,
                "target_identity_id": req.target_identity,
                "require_user_session": require_user_session,
                "service_instance_id": req.service_instance_id,
                "credential_key": req.credential_key,
                "via": req.via,
                // Only ever true for a mint that was refused once and retried
                // with `force`, so its presence in the log is the record of a
                // deliberate credential replacement.
                "force": req.force,
            }),
            description: None,
            ip_address: req.ip_address,
        })
        .await;

    let audience = crate::services::events::audience::for_secret_request(
        &scope,
        req.requested_by,
        req.target_identity,
    )
    .await;
    let event = crate::services::events::EventDraft {
        org_id: req.org_id,
        event_type: crate::services::events::EventType::SecretRequestCreated,
        payload: serde_json::json!({
            "request_id": &request_id,
            "secret_name": req.secret_name,
            "identity_id": req.target_identity,
            "requested_by": req.requested_by,
            "service_id": req.service_instance_id,
            "credential_key": req.credential_key,
            "expires_at": crate::routes::util::fmt_time(expires_at),
            "via": req.via,
        }),
        audience,
    };

    Ok(MintedRequest {
        request_id,
        token,
        url,
        short_url,
        expires_at,
        event,
    })
}

// ── Bundle ────────────────────────────────────────────────────────────────

/// Mint one setup link per unbound credential slot and assemble the bundle.
///
/// All-or-nothing from the caller's side: the first failure returns, and
/// `kernel_create_service` drops the whole bundle rather than handing over a
/// partial set of links that silently cannot finish the setup. Rows already
/// written stay — they are single-use, expire on their own, and burning them
/// would need a transaction this path does not hold.
#[allow(clippy::too_many_arguments)]
pub async fn mint_bundle(
    db: &sqlx::PgPool,
    http_client: &reqwest::Client,
    config: &Config,
    org_id: Uuid,
    owner_identity_id: Uuid,
    requested_by: Uuid,
    service_instance_id: Uuid,
    slots: &[SecretSlot],
    force: bool,
) -> Result<SetupBundle, AppError> {
    // Captured once for the whole bundle so every link in it agrees, the way
    // the single-request mint paths capture it.
    let require_user_session =
        !overslash_db::repos::org::get_allow_unsigned_secret_provide(db, org_id)
            .await?
            .unwrap_or(true);

    // On a forced create, read the versions being superseded *before* any link
    // is minted, so the warning names the value that was actually there when
    // the caller asked. Skipped entirely when not forcing: `mint` refuses on
    // collision in that case, so there is nothing to warn about.
    let warnings = if force {
        let scope = OrgScope::new(org_id, db.clone());
        let candidates: Vec<(Option<String>, String)> = slots
            .iter()
            .map(|s| (Some(s.key.clone()), s.default_secret_name.clone()))
            .collect();
        conflicting_secret_names(&scope, &candidates)
            .await?
            .into_iter()
            .map(|c| SetupWarning {
                code: "overwrites_existing_secret",
                message: format!(
                    "opening this link replaces the current value of secret \
                     '{}' (v{}). The old version stays restorable.",
                    c.secret_name, c.current_version
                ),
                credential_key: c.credential_key.unwrap_or_default(),
                secret_name: c.secret_name,
                current_version: c.current_version,
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut requests = Vec::with_capacity(slots.len());
    let mut events = Vec::with_capacity(slots.len());
    let mut first: Option<(String, Option<String>, time::OffsetDateTime)> = None;
    for slot in slots {
        let minted = mint(
            db,
            http_client,
            config,
            MintRequest {
                org_id,
                target_identity: owner_identity_id,
                requested_by,
                secret_name: &slot.default_secret_name,
                // The slot's authored label, when it has one.
                // `x-overslash-label` is optional and most shipped templates
                // omit it, so this is usually `None` — and `None` is what the
                // pages branch on to omit the Reason row entirely. Passing
                // `Some("")` would render an empty row instead.
                reason: Some(slot.label.trim()).filter(|l| !l.is_empty()),
                ttl_seconds: SETUP_LINK_TTL_SECS,
                require_user_session,
                service_instance_id: Some(service_instance_id),
                credential_key: Some(&slot.key),
                force,
                via: "create_service",
                ip_address: None,
            },
        )
        .await?;
        if first.is_none() {
            first = Some((
                minted.url.clone(),
                minted.short_url.clone(),
                minted.expires_at,
            ));
        }
        events.push(minted.event);

        requests.push(SetupRequestRef {
            request_id: minted.request_id,
            credential_key: slot.key.clone(),
            secret_name: slot.default_secret_name.clone(),
            setup_url: minted.url,
            short_url: minted.short_url,
        });
    }

    // One call, so a two-slot bundle's events land in the order they were
    // authored rather than racing each other's inserts.
    crate::services::events::emit_all(db.clone(), http_client.clone(), events);

    let (setup_url, short_url, expires_at) = first.ok_or_else(|| {
        // Unreachable from `kernel_create_service`, which checks first. A
        // caller that asks for a bundle over no slots has asked for nothing.
        AppError::Internal("mint_bundle called with no slots".into())
    })?;
    Ok(SetupBundle {
        setup_url,
        short_url,
        requests,
        expires_at: crate::routes::util::fmt_time(expires_at),
        warnings,
    })
}

pub(crate) fn sha256(s: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().to_vec()
}
