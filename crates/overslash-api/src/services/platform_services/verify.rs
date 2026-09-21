//! Whether a new service instance is gated behind its credential probe.
//!
//! One decision, with enough reasoning attached that it wants its own file:
//! getting it wrong in either direction is silent. Gate too little and a
//! service goes live on a credential nothing checked, which is the whole thing
//! this exists to stop. Gate too much and you create an instance nobody can
//! release — see the note on agents in [`resolve_create_status`] — which the
//! sweeper then deletes a day later without anyone learning why.

use uuid::Uuid;

use super::types::CreateServiceInput;
use crate::error::AppError;

/// The lifecycle status a new instance is created in.
///
/// `pending_setup` means the instance exists but is not callable and does not
/// appear in search, until its template-declared probe comes back green
/// through `POST /v1/services/{id}/activate`. See migration 119 for why that is
/// a status of its own rather than a reuse of `draft`.
///
/// The default arm gates iff **the template declares a probe and a slot is
/// unbound** — which is precisely the case where this function's caller is
/// about to mint a setup link, so a human will land on a page we control,
/// holding a session (setup links force one), and their browser will run the
/// probe. Every other flow is left live, because nothing in it can produce a
/// verdict and a gate nobody can lift is an instance that dies in the sweeper:
///
/// - **OAuth.** Auto-connect returns `connect.auth_url`; the dance ends in a
///   server-side callback with no caller to run a probe as.
/// - **Credentials already bound**, or `skip_credentials`, or an org-level
///   instance with no owner — the three cases the auto-mint itself skips, so
///   there would be no link and no page. In the first, typically an agent
///   naming a vault secret it knows exists, the agent could not lift the gate
///   either: `POST /v1/services/{id}/activate` is owner-or-admin and an agent
///   is deliberately not an ancestor of its owner-user
///   ([`crate::services::permission_chain::caller_may_manage_owned`]).
/// - **No probe declared.** 4 of the 24 shipped templates; there is no verdict
///   to wait for, so gating would strand the instance permanently.
pub(super) fn resolve_create_status<'a>(
    input: &'a CreateServiceInput,
    template: &overslash_core::types::ServiceDefinition,
    pending_slots: &[overslash_core::types::SecretSlot],
    owner_identity_id: Option<Uuid>,
) -> Result<&'a str, AppError> {
    let has_probe = template.test_action().is_some();
    // Exactly the auto-mint's own condition, restated — not an approximation
    // of it. Gating a create that mints no link produces an instance with no
    // handshake to hand anyone: an org-level instance (no owner to store the
    // secret under, so `mint` is skipped) or a `skip_credentials` caller that
    // said it would wire the credentials up itself. Either would sit
    // `pending_setup` until the sweeper took it.
    let will_mint_link = !input.skip_credentials.unwrap_or(false)
        && owner_identity_id.is_some()
        && !pending_slots.is_empty();
    match input.verify {
        Some(false) => Ok(&input.status),
        // A hard error rather than a silent downgrade: the caller asked for a
        // guarantee this template cannot deliver, and answering `active`
        // without saying so is how a dashboard ends up reporting a service
        // verified that nothing ever checked.
        Some(true) if !has_probe => Err(AppError::BadRequest(format!(
            "template '{}' declares no test action, so `verify` cannot be honoured",
            template.key
        ))),
        Some(true) => Ok(PENDING_SETUP),
        None if has_probe && will_mint_link => Ok(PENDING_SETUP),
        None => Ok(&input.status),
    }
}

/// The status of an instance whose credentials have not been proven to work.
pub const PENDING_SETUP: &str = "pending_setup";

#[cfg(test)]
mod create_status_tests {
    use super::*;
    use overslash_core::types::{
        Risk, Runtime, SecretSlot, SecretSource, ServiceAction, ServiceDefinition,
    };
    use std::collections::HashMap;

    fn def(with_probe: bool) -> ServiceDefinition {
        let mut action = ServiceAction {
            risk: Risk::Read.into(),
            ..Default::default()
        };
        if with_probe {
            action.test = Some(Default::default());
        }
        ServiceDefinition {
            key: "resend".into(),
            display_name: "Resend".into(),
            description: None,
            hosts: vec!["api.resend.test".into()],
            category: None,
            hidden: false,
            icon: None,
            auth: Vec::new(),
            secrets: Vec::new(),
            config: Vec::new(),
            actions: HashMap::from([("list_domains".to_string(), action)]),
            default_timeout_ms: None,
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    fn slot() -> SecretSlot {
        SecretSlot {
            key: "token".into(),
            label: "API key".into(),
            description: String::new(),
            default_secret_name: "resend_key".into(),
            source: SecretSource::Instance,
            optional: false,
        }
    }

    fn input(verify: Option<bool>) -> CreateServiceInput {
        CreateServiceInput {
            template_key: "resend".into(),
            status: "active".into(),
            verify,
            ..Default::default()
        }
    }

    /// The default rule, and the flow the gate exists for: a template that can
    /// prove itself, and a credential nobody has supplied yet — so a setup
    /// link is about to be minted and a human with a session will run the
    /// probe.
    #[test]
    fn an_unbound_slot_on_a_probeable_template_is_gated() {
        assert_eq!(
            resolve_create_status(&input(None), &def(true), &[slot()], Some(Uuid::nil())).unwrap(),
            PENDING_SETUP
        );
    }

    /// Nothing in this flow can produce a verdict: the caller bound the
    /// credential itself, so no link is minted and nobody lands on a page. An
    /// agent could not lift the gate either — `/activate` is owner-or-admin
    /// and an agent is not an ancestor of its owner-user — so gating here
    /// would create an instance that only the sweeper could resolve.
    #[test]
    fn an_already_bound_credential_is_not_gated() {
        assert_eq!(
            resolve_create_status(&input(None), &def(true), &[], Some(Uuid::nil())).unwrap(),
            "active"
        );
    }

    /// No probe, no verdict, no way out of the gate. Four of the shipped
    /// templates are in this position deliberately.
    #[test]
    fn a_template_without_a_probe_is_not_gated() {
        assert_eq!(
            resolve_create_status(&input(None), &def(false), &[slot()], Some(Uuid::nil())).unwrap(),
            "active"
        );
    }

    /// The dashboard wizard's path. It probes whether or not a link was
    /// minted, so it asks for the gate explicitly rather than relying on the
    /// structural rule.
    #[test]
    fn verify_true_gates_even_with_the_credential_bound() {
        assert_eq!(
            resolve_create_status(&input(Some(true)), &def(true), &[], Some(Uuid::nil())).unwrap(),
            PENDING_SETUP
        );
    }

    /// A hard error, not a silent downgrade to `active`. Answering "fine, it's
    /// live" to a caller that asked for verification is how a dashboard ends
    /// up reporting a service checked that nothing ever checked.
    #[test]
    fn verify_true_on_a_probeless_template_is_an_error() {
        let err = resolve_create_status(
            &input(Some(true)),
            &def(false),
            &[slot()],
            Some(Uuid::nil()),
        )
        .unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(ref m) if m.contains("declares no test action")),
            "{err:?}"
        );
    }

    /// No owner means `mint_bundle` is skipped — an org-level instance has no
    /// identity to store the secret under. Gating one would leave it
    /// `pending_setup` with no link for anyone to open, which is the sweeper's
    /// problem and nobody else's. The rule mirrors the mint's own condition
    /// rather than approximating it.
    #[test]
    fn an_org_level_instance_is_not_gated() {
        assert_eq!(
            resolve_create_status(&input(None), &def(true), &[slot()], None).unwrap(),
            "active"
        );
    }

    /// Same reasoning: the caller said it would wire the credentials up
    /// itself, so no link is minted and there is no page to run a probe from.
    #[test]
    fn skip_credentials_is_not_gated() {
        let mut i = input(None);
        i.skip_credentials = Some(true);
        assert_eq!(
            resolve_create_status(&i, &def(true), &[slot()], Some(Uuid::nil())).unwrap(),
            "active"
        );
    }

    /// The escape hatch, for a caller that will wire the credentials up itself.
    #[test]
    fn verify_false_always_creates_live() {
        assert_eq!(
            resolve_create_status(
                &input(Some(false)),
                &def(true),
                &[slot()],
                Some(Uuid::nil())
            )
            .unwrap(),
            "active"
        );
    }
}
