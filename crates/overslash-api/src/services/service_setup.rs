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
//! `kernel_create_service` cannot drift apart. Before this they each rebuilt
//! the mint by hand, which is how the TTL came to differ between the first
//! two.
//!
//! The OAuth half of setup has no equivalent here on purpose: it is already
//! carried end to end by `oauth_flows` + `service_instances.connection_id`,
//! and `kernel_create_service` surfaces it as the `connect` bundle this
//! module's `setup` bundle is modelled on.

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_core::types::{SecretSlot, SecretSource, ServiceDefinition};
use overslash_db::repos::secret_request;
use overslash_db::repos::service_instance::{CredentialsMap, ServiceInstanceRow};
use overslash_db::scopes::OrgScope;

use crate::config::Config;
use crate::error::AppError;
use crate::services::jwt::{self, SECRET_REQUEST_KIND, SecretRequestClaims};
use crate::services::short_url;

/// Dashboard route the minted URL points at when the request names a service.
/// A bare secret request keeps the older, service-less page.
const SETUP_PATH: &str = "/services/setup";

/// TTL for an auto-minted setup link.
///
/// One hour, matching the MCP `request_secret` default. A setup link is handed
/// straight to a human who is expected to act on it now; a longer window
/// mostly means more live bearer URLs sitting in chat transcripts. A caller
/// who needs longer mints its own via `POST /v1/secrets/requests`, which takes
/// `ttl_seconds`.
const SETUP_LINK_TTL_SECS: i64 = 3600;
const PROVIDE_PATH: &str = "/secrets/provide";

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
}

#[derive(Serialize, Debug)]
pub struct SetupRequestRef {
    pub request_id: String,
    /// The template securityScheme slot key this link fills.
    pub credential_key: String,
    /// The vault name the value will be stored under.
    pub secret_name: String,
    pub setup_url: String,
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
    pub require_user_session: bool,
    /// Both `Some` or both `None` — the DB check constraint says so, and
    /// [`validate_binding`] is what establishes it for a caller-supplied pair.
    pub service_instance_id: Option<Uuid>,
    pub credential_key: Option<&'a str>,
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
    let now = time::OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(req.ttl_seconds);
    let request_id = format!("req_{}", Uuid::new_v4().simple());

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
        req.require_user_session,
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
    let short_url = match (
        config.oversla_sh_base_url.as_deref(),
        config.oversla_sh_api_key.as_deref(),
    ) {
        (Some(base), Some(key)) => {
            short_url::mint_with_client(http_client, base, key, &url, expires_at).await
        }
        _ => None,
    };

    Ok(MintedRequest {
        request_id,
        token,
        url,
        short_url,
        expires_at,
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
) -> Result<SetupBundle, AppError> {
    // Captured once for the whole bundle so every link in it agrees, the way
    // the single-request mint paths capture it.
    let require_user_session =
        !overslash_db::repos::org::get_allow_unsigned_secret_provide(db, org_id)
            .await?
            .unwrap_or(true);

    let mut requests = Vec::with_capacity(slots.len());
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
        requests.push(SetupRequestRef {
            request_id: minted.request_id,
            credential_key: slot.key.clone(),
            secret_name: slot.default_secret_name.clone(),
            setup_url: minted.url,
        });
    }

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
    })
}

// ── Slots ─────────────────────────────────────────────────────────────────

/// The instance-source credential slots this instance has no binding for yet.
///
/// The same filter the search setup-hint used to apply inline: `source:
/// instance` (an `org` slot is provisioned once, org-wide, by an admin — not
/// by whoever clicks a setup link), not already bound, and carrying a
/// `default_secret_name` to store the value under. A slot with no default
/// name is a supported shape — `template_validation::core::auth` requires a
/// default only for org-source slots — but there is no name to mint a request
/// for, so it surfaces at call time in `credential_missing` instead.
pub fn unbound_instance_slots(
    template: &ServiceDefinition,
    credentials: &CredentialsMap,
    legacy_secret_name: Option<&str>,
) -> Vec<SecretSlot> {
    let instance_slots: Vec<SecretSlot> = template
        .all_slots()
        .into_iter()
        .filter(|s| s.source == SecretSource::Instance && !s.key.is_empty())
        .collect();
    // The legacy scalar `secret_name` binds the *sole* instance slot, which is
    // how every pre-slots instance is stored. Treat it as a binding for that
    // one slot so an instance created the old way is not asked to provide a
    // value it already has.
    let legacy_covers_sole_slot =
        legacy_secret_name.is_some_and(|n| !n.is_empty()) && instance_slots.len() == 1;

    instance_slots
        .into_iter()
        .filter(|s| {
            !s.optional
                && !s.default_secret_name.is_empty()
                && !credentials.contains_key(&s.key)
                && !legacy_covers_sole_slot
        })
        .collect()
}

// ── Mint-time validation of a caller-supplied binding ─────────────────────

/// Resolve and check a caller-supplied `(service_id, credential_key)` pair.
///
/// This is the *only* place the pair is checked. Fulfilment runs from a public
/// route holding nothing but a capability token, so it binds the slot the row
/// names without re-deriving anything — which is exactly why the check here
/// has to be complete: the caller may manage the instance, and the key names a
/// real instance-source slot of its template.
///
/// The authorization half is not optional and not a formality. A minted link
/// is a live capability to *write* `service_instances.credentials[key]`, and
/// `OrgScope::get_service_instance` filters by tenant alone — so without the
/// ceiling check any org member could mint a link that rebinds another user's
/// credential slot, or an org-level instance's, and hand themselves the URL.
///
/// The test is the **ceiling user**, matching `kernel_update_service` rather
/// than `routes::services::require_owner_or_admin`'s ancestry: instances are
/// owned by users, and an agent is deliberately not an ancestor of its own
/// owner-user, so ancestry would refuse an agent the instance it just created
/// — the flow this whole surface exists to serve.
pub async fn validate_binding(
    scope: &OrgScope,
    registry: &overslash_core::registry::ServiceRegistry,
    identity_id: Option<Uuid>,
    access_level: AccessLevel,
    service_id: Uuid,
    credential_key: Option<&str>,
) -> Result<(ServiceInstanceRow, String), AppError> {
    let row = scope
        .get_service_instance(service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    let auth_identity = identity_id.ok_or_else(|| {
        AppError::BadRequest("binding a credential to a service requires an identity".into())
    })?;
    crate::services::platform_services::require_owned_by_ceiling_or_admin(
        scope,
        &row,
        auth_identity,
        access_level,
    )
    .await?;

    let template = crate::services::platform_services::resolve_template_definition(
        scope.db(),
        registry,
        scope.org_id(),
        identity_id,
        &row.template_key,
    )
    .await?;

    let slots: Vec<SecretSlot> = template
        .all_slots()
        .into_iter()
        .filter(|s| s.source == SecretSource::Instance && !s.key.is_empty())
        .collect();

    let key = match credential_key {
        Some(k) => k.to_string(),
        // No key named: only unambiguous when the template has exactly one
        // instance slot, which is the shape every shipped template has. A
        // template with two gets a 400 naming both rather than a coin flip.
        None => match slots.as_slice() {
            [only] => only.key.clone(),
            [] => {
                return Err(AppError::BadRequest(format!(
                    "template '{}' declares no per-instance credential slot to bind",
                    row.template_key
                )));
            }
            many => {
                return Err(AppError::BadRequest(format!(
                    "template '{}' declares several credential slots ({}); name one with `credential_key`",
                    row.template_key,
                    many.iter()
                        .map(|s| s.key.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        },
    };

    if !slots.iter().any(|s| s.key == key) {
        return Err(AppError::BadRequest(format!(
            "credential_key '{key}' is not a per-instance credential slot of template '{}'",
            row.template_key
        )));
    }

    Ok((row, key))
}

pub(crate) fn sha256(s: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().to_vec()
}
