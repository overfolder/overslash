//! Which credential slots a template declares, and whether a caller may bind
//! one.
//!
//! Split from `mod.rs` at the seam the file already drew with its own section
//! banners: everything here answers a question about the *template* and the
//! caller's authority over it, and none of it mints anything. `mint` and
//! `mint_bundle` are that module's job, and they read these answers.
//!
//! The slot-selection predicate in particular wants one home: "which slots
//! does an instance have to bind" is asked by the auto-mint, by the
//! verification gate (D-NEXT) and by the secret-name conflict check (D85), and
//! three copies of it would drift.

use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_core::types::{SecretSlot, SecretSource, ServiceDefinition};
use overslash_db::repos::service_instance::{CredentialsMap, ServiceInstanceRow};
use overslash_db::scopes::OrgScope;

use crate::error::AppError;

// ── Slots ─────────────────────────────────────────────────────────────────

/// Every credential slot an *instance* binds: `source: instance`, with a key.
///
/// The one place the *slot-selection* predicate is written. An `org` slot is
/// provisioned once, org-wide, by an admin — never by whoever clicks a setup
/// link — and a slot with an empty key cannot key a binding at all.
///
/// Whether a slot is *bound* is a separate question with its own subtleties
/// (the legacy scalar alias, composed credentials) that
/// `status::derive_credentials_status` owns for the badge; [`is_bound`] is the
/// single-slot half of it, shared so the two cannot disagree.
pub fn instance_slots(template: &ServiceDefinition) -> Vec<SecretSlot> {
    template
        .all_slots()
        .into_iter()
        .filter(|s| s.source == SecretSource::Instance && !s.key.is_empty())
        .collect()
}

/// Every required credential slot this instance still needs a value for.
///
/// "Is this service provisioned?" — the question the setup page's *remaining*
/// list and the fulfilment event both answer. Deliberately includes a slot
/// with no `default_secret_name`: nothing can mint a link for it, but it is
/// still missing, and reporting an instance as complete because the one
/// outstanding credential happens to be unmintable is the worst of the
/// available answers.
pub fn unprovisioned_instance_slots(
    template: &ServiceDefinition,
    credentials: &CredentialsMap,
    legacy_secret_name: Option<&str>,
) -> Vec<String> {
    // The legacy scalar `secret_name` binds the *sole* instance slot, which is
    // how every pre-slots instance is stored. Treat it as a binding for that
    // one slot so an instance created the old way is not reported as missing a
    // value it already has.
    //
    // Counted over *all* instance-source slots, unkeyed ones included, which
    // is what `derive_credentials_status` counts. `instance_slots` drops the
    // unkeyed slot because nothing can key a binding by it — but the scalar
    // alias stood for that credential too, so a template with one keyed and
    // one unkeyed slot is not the single-slot shape the alias can vouch for.
    // Counting only keyed slots here would report "provisioned" while the
    // badge reads `NeedsAuthentication`.
    let sole_instance_slot = template
        .all_slots()
        .iter()
        .filter(|s| s.source == SecretSource::Instance)
        .count()
        <= 1;
    let legacy_covers_sole_slot =
        legacy_secret_name.is_some_and(|n| !n.is_empty()) && sole_instance_slot;
    if legacy_covers_sole_slot {
        return Vec::new();
    }

    instance_slots(template)
        .into_iter()
        .filter(|s| !s.optional && !is_bound(credentials, &s.key))
        .map(|s| s.key)
        .collect()
}

/// The slots a setup link can be minted for.
///
/// [`unprovisioned_instance_slots`] minus the ones carrying no
/// `default_secret_name` to store the value under. A slot with no default name
/// is a supported shape — `template_validation::core::auth` requires a default
/// only for org-source slots — but there is no vault name to mint a request
/// against, so it surfaces at call time in `credential_missing` instead.
///
/// Narrower than "what is still missing" on purpose: the two are different
/// questions, and answering the second with the first is what lets an instance
/// read as complete while a credential is outstanding.
pub fn unbound_instance_slots(
    template: &ServiceDefinition,
    credentials: &CredentialsMap,
    legacy_secret_name: Option<&str>,
) -> Vec<SecretSlot> {
    let missing = unprovisioned_instance_slots(template, credentials, legacy_secret_name);
    instance_slots(template)
        .into_iter()
        .filter(|s| !s.default_secret_name.is_empty() && missing.contains(&s.key))
        .collect()
}

/// Whether a slot's binding is one the *call path* would resolve.
///
/// Present-and-non-empty, matching `derive_credentials_status` and
/// `auth_envelopes`. Key presence alone is not enough: an empty-string value
/// would read as bound here — so no setup link gets minted — while execution
/// reports `credential_missing`, leaving an uncallable service with no link to
/// fix it.
pub fn is_bound(credentials: &CredentialsMap, key: &str) -> bool {
    credentials.get(key).is_some_and(|n| !n.is_empty())
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
    // The *caller*, for the authorization check only. Template resolution
    // uses the instance's owner — see below.
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

    // Resolved as the instance's *owner*, not the caller. The user tier is
    // keyed on that identity, so an agent minting a link for its owner-user's
    // instance — the flow this whole surface exists for — would miss a
    // user-tier template and fail with "template not found". Every other
    // instance-view path passes `owner_identity_id` for the same reason.
    let template = crate::services::platform_services::resolve_template_definition(
        scope.db(),
        registry,
        scope.org_id(),
        row.owner_identity_id,
        &row.template_key,
    )
    .await?;

    let key = resolve_slot_key(&template, credential_key)?;
    Ok((row, key))
}

/// Pick the slot a binding names, or infer it.
///
/// Split out of [`validate_binding`] because it is the whole of that
/// function's *logic* and none of its I/O: the multi-slot arm produces a
/// user-facing 400 that no integration test can reach, since no shipped
/// template declares two instance slots.
fn resolve_slot_key(
    template: &ServiceDefinition,
    credential_key: Option<&str>,
) -> Result<String, AppError> {
    let slots = instance_slots(template);
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
                    template.key
                )));
            }
            many => {
                return Err(AppError::BadRequest(format!(
                    "template '{}' declares several credential slots ({}); name one with `credential_key`",
                    template.key,
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
            template.key
        )));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use overslash_core::types::service::{SecretSlot, TokenInjection};
    use overslash_core::types::{Runtime, ServiceAuth};
    use std::collections::HashMap;

    fn injection() -> TokenInjection {
        TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: None,
        }
    }

    fn slot(key: &str, secret_name: &str, source: SecretSource) -> SecretSlot {
        SecretSlot {
            key: key.into(),
            label: key.into(),
            description: String::new(),
            default_secret_name: secret_name.into(),
            source,
            optional: false,
        }
    }

    fn secret_auth(scheme: &str, default_secret_name: &str, slots: Vec<String>) -> ServiceAuth {
        ServiceAuth::Secret {
            template: None,
            slots,
            config_keys: Vec::new(),
            scheme: scheme.into(),
            label: scheme.into(),
            description: String::new(),
            default_secret_name: default_secret_name.into(),
            injection: injection(),
            secret_source: SecretSource::Instance,
            optional: false,
        }
    }

    fn def(auth: Vec<ServiceAuth>, secrets: Vec<SecretSlot>) -> ServiceDefinition {
        ServiceDefinition {
            key: "acme".into(),
            display_name: "Acme".into(),
            description: None,
            hosts: vec!["api.acme.test".into()],
            category: None,
            hidden: false,
            icon: None,
            auth,
            secrets,
            config: Vec::new(),
            actions: HashMap::new(),
            default_timeout_ms: None,
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    fn keys(slots: Vec<SecretSlot>) -> Vec<String> {
        slots.into_iter().map(|s| s.key).collect()
    }

    /// The common shape: one implicit slot named after the scheme.
    #[test]
    fn a_single_unbound_slot_is_asked_for() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            Vec::new(),
        );
        assert_eq!(
            keys(unbound_instance_slots(&d, &CredentialsMap::new(), None)),
            vec!["token"]
        );
    }

    #[test]
    fn a_bound_slot_is_not_asked_for_again() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            Vec::new(),
        );
        let bound = CredentialsMap::from([("token".to_string(), "acme_api_key".to_string())]);
        assert!(unbound_instance_slots(&d, &bound, None).is_empty());
    }

    /// The legacy scalar `secret_name` is how every pre-slots instance stores
    /// its one credential. Asking for a value the instance already has would
    /// be a setup link nobody needs to open.
    #[test]
    fn the_legacy_scalar_covers_a_sole_slot() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            Vec::new(),
        );
        assert!(
            unbound_instance_slots(&d, &CredentialsMap::new(), Some("acme_api_key")).is_empty()
        );
        // …and an empty one covers nothing.
        assert_eq!(
            keys(unbound_instance_slots(&d, &CredentialsMap::new(), Some(""))),
            vec!["token"]
        );
    }

    /// An `org` slot is provisioned once, org-wide, by an admin — never by
    /// whoever clicks a setup link.
    #[test]
    fn org_source_slots_are_never_asked_for() {
        let d = def(
            vec![secret_auth(
                "basic",
                "acme_user",
                vec!["acme_user".into(), "acme_shared".into()],
            )],
            vec![
                slot("acme_user", "acme_user", SecretSource::Instance),
                slot("acme_shared", "acme_shared", SecretSource::Org),
            ],
        );
        assert_eq!(
            keys(unbound_instance_slots(&d, &CredentialsMap::new(), None)),
            vec!["acme_user"]
        );
    }

    /// No default name means no vault name to mint a request for. The slot is
    /// a supported shape and surfaces at call time in `credential_missing`
    /// instead.
    #[test]
    fn a_slot_without_a_default_name_is_not_asked_for() {
        let d = def(
            vec![secret_auth(
                "basic",
                "acme_user",
                vec!["acme_user".into(), "acme_nameless".into()],
            )],
            vec![
                slot("acme_user", "acme_user", SecretSource::Instance),
                slot("acme_nameless", "", SecretSource::Instance),
            ],
        );
        assert_eq!(
            keys(unbound_instance_slots(&d, &CredentialsMap::new(), None)),
            vec!["acme_user"]
        );
    }

    #[test]
    fn an_optional_slot_is_not_asked_for() {
        let mut optional = slot("acme_extra", "acme_extra", SecretSource::Instance);
        optional.optional = true;
        let d = def(
            vec![secret_auth(
                "basic",
                "acme_user",
                vec!["acme_user".into(), "acme_extra".into()],
            )],
            vec![
                slot("acme_user", "acme_user", SecretSource::Instance),
                optional,
            ],
        );
        assert_eq!(
            keys(unbound_instance_slots(&d, &CredentialsMap::new(), None)),
            vec!["acme_user"]
        );
    }

    /// Two unbound slots means two links. No shipped template declares two,
    /// which is exactly why this is a unit test — and the legacy scalar must
    /// *not* be read as covering one of them, since it is only unambiguous
    /// when there is a single slot to cover.
    #[test]
    fn two_unbound_slots_are_both_asked_for() {
        let d = def(
            vec![secret_auth(
                "basic",
                "acme_user",
                vec!["acme_user".into(), "acme_pass".into()],
            )],
            vec![
                slot("acme_user", "acme_user", SecretSource::Instance),
                slot("acme_pass", "acme_pass", SecretSource::Instance),
            ],
        );
        let mut got = keys(unbound_instance_slots(&d, &CredentialsMap::new(), None));
        got.sort();
        assert_eq!(got, vec!["acme_pass", "acme_user"]);

        let mut with_legacy = keys(unbound_instance_slots(
            &d,
            &CredentialsMap::new(),
            Some("acme_user"),
        ));
        with_legacy.sort();
        assert_eq!(
            with_legacy,
            vec!["acme_pass", "acme_user"],
            "the scalar alias is ambiguous with several slots and covers none"
        );
    }

    // ── resolve_slot_key ───────────────────────────────────────────────

    fn err_message(e: AppError) -> String {
        match e {
            AppError::BadRequest(m) => m,
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// The documented happy path: every shipped template declares one
    /// instance slot, so a caller never has to name it.
    #[test]
    fn a_sole_slot_is_inferred() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            Vec::new(),
        );
        assert_eq!(resolve_slot_key(&d, None).unwrap(), "token");
    }

    /// Two slots is a coin flip, and a link that binds the wrong credential is
    /// worse than one that was never minted. No shipped template declares two,
    /// which is exactly why this is a unit test.
    #[test]
    fn several_slots_refuse_to_be_guessed_and_name_both() {
        let d = def(
            vec![secret_auth(
                "basic",
                "acme_user",
                vec!["acme_user".into(), "acme_pass".into()],
            )],
            vec![
                slot("acme_user", "acme_user", SecretSource::Instance),
                slot("acme_pass", "acme_pass", SecretSource::Instance),
            ],
        );
        let msg = err_message(resolve_slot_key(&d, None).unwrap_err());
        assert!(msg.contains("acme_user"), "{msg}");
        assert!(msg.contains("acme_pass"), "{msg}");
        assert!(msg.contains("credential_key"), "{msg}");
        // Naming one resolves it.
        assert_eq!(
            resolve_slot_key(&d, Some("acme_pass")).unwrap(),
            "acme_pass"
        );
    }

    /// An OAuth template has nothing per-instance to bind.
    #[test]
    fn no_instance_slot_is_refused() {
        let d = def(Vec::new(), Vec::new());
        let msg = err_message(resolve_slot_key(&d, None).unwrap_err());
        assert!(msg.contains("no per-instance credential slot"), "{msg}");
    }

    /// Fulfilment re-derives nothing, so a key that names no slot has to be
    /// refused here or it is never refused at all.
    #[test]
    fn an_unknown_key_is_refused() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            Vec::new(),
        );
        let msg = err_message(resolve_slot_key(&d, Some("nope")).unwrap_err());
        assert!(msg.contains("nope"), "{msg}");
    }

    /// An `org` slot is admin-provisioned org-wide; a setup link must not be
    /// able to name one even explicitly.
    #[test]
    fn an_org_slot_cannot_be_named() {
        let d = def(
            vec![secret_auth(
                "basic",
                "acme_user",
                vec!["acme_user".into(), "acme_shared".into()],
            )],
            vec![
                slot("acme_user", "acme_user", SecretSource::Instance),
                slot("acme_shared", "acme_shared", SecretSource::Org),
            ],
        );
        assert!(resolve_slot_key(&d, Some("acme_shared")).is_err());
        assert_eq!(resolve_slot_key(&d, None).unwrap(), "acme_user");
    }

    /// One bound, one not: only the gap is asked for. This is the state the
    /// setup page's "still needs N more" copy renders.
    #[test]
    fn a_partially_bound_template_asks_only_for_the_gap() {
        let d = def(
            vec![secret_auth(
                "basic",
                "acme_user",
                vec!["acme_user".into(), "acme_pass".into()],
            )],
            vec![
                slot("acme_user", "acme_user", SecretSource::Instance),
                slot("acme_pass", "acme_pass", SecretSource::Instance),
            ],
        );
        let bound = CredentialsMap::from([("acme_user".to_string(), "acme_user".to_string())]);
        assert_eq!(
            keys(unbound_instance_slots(&d, &bound, None)),
            vec!["acme_pass"]
        );
    }
}
