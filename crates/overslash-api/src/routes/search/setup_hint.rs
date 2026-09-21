//! How a search row advertises what it still needs to become callable.
//!
//! A row that names a service the caller cannot use yet is only half an
//! answer. `AuthStatus` carries the diagnosis (`type`, `connected`) and, when
//! the row is not callable, `setup`: the ordered platform calls that fix it.
//! Agents read this at exactly the moment they discover the gap, so it is the
//! difference between self-service and handing the job back to a human.

use serde::Serialize;

use overslash_core::types::{ServiceAuth, ServiceDefinition};

#[derive(Serialize, Clone)]
pub(super) struct AuthStatus {
    /// `"oauth"` or `"secret"`. Mirrors `ServiceAuth` so agents don't have
    /// to crack open the template themselves.
    ///
    /// This string is hand-built, not derived from `ServiceAuth`'s serde
    /// tag, so `ServiceAuth::Secret`'s `alias = "api_key"` does NOT apply:
    /// it only rescues *inbound* parsing. Outbound, this field emits
    /// `"secret"` where it used to emit `"api_key"` — a deliberate break for
    /// any client branching on the old discriminant. Agents read the current
    /// vocabulary from SKILL.md, and the dashboard ships with the API.
    #[serde(rename = "type")]
    kind: String,
    /// OAuth provider key when `kind == "oauth"`. Absent for secret-based auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    /// `true` when this row represents a configured instance the caller can
    /// call now; `false` for `setup_required` catalog rows. Read by the
    /// ranking pass, which floats callable rows above catalog ones.
    pub(super) connected: bool,
    /// The calls that turn this row into something callable, in order.
    /// Present only when `connected` is false — i.e. exactly when an agent
    /// has found the thing it wants and cannot yet use it.
    ///
    /// Without this, discovery dead-ends: the row says a credential is
    /// missing and names neither the call that supplies one nor the fact that
    /// the agent may make it itself. In practice agents fell back to asking
    /// their human to go to the dashboard. Each step is directly callable as
    /// `overslash_call(service="overslash", action=<action>, params=<params>)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<Vec<SetupStep>>,
}

/// One call in an [`AuthStatus::setup`] chain.
#[derive(Serialize, Clone)]
pub(super) struct SetupStep {
    /// A platform action key on the `overslash` service.
    action: &'static str,
    /// Pre-filled arguments. Partial by nature — `create_service` also takes a
    /// `name`, which is the caller's to choose.
    params: serde_json::Map<String, serde_json::Value>,
    /// What to do with what the call returns, when that is not obvious.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'static str>,
}

/// `awaiting_setup`: the caller already has an instance of this template
/// sitting in `pending_setup`. Not callable, so `connected` stays false — but
/// the chain to fix it is "finish the one you have", not "make another".
pub(super) fn build_auth_status(
    def: &ServiceDefinition,
    connected: bool,
    awaiting_setup: bool,
) -> AuthStatus {
    // Pick the first declared auth method as the primary face the caller
    // sees. Templates that mix auth methods (rare) still surface here with
    // the preferred one first — exactly how the dashboard displays them.
    let (kind, provider) = match def.auth.first() {
        Some(ServiceAuth::OAuth { provider, .. }) => ("oauth".into(), Some(provider.clone())),
        Some(ServiceAuth::Secret { .. }) => ("secret".into(), None),
        None => ("none".into(), None),
    };
    let setup = (!connected).then(|| {
        if awaiting_setup {
            finish_setup_steps()
        } else {
            build_setup_steps(def)
        }
    });
    AuthStatus {
        kind,
        provider,
        connected,
        setup,
    }
}

/// The chain for a template the caller already has a `pending_setup` instance
/// of.
///
/// Calling `create_service` again is the wrong move twice over: with the same
/// name it is a `409` (the unique index does not know about lifecycle status),
/// and with a different one it leaves a second orphan for the sweeper. The
/// instance exists and its credential handshake may well be in someone's chat
/// window already — what is missing is a green probe.
///
/// `get_service` rather than `list_services` because the caller needs one
/// row's `status`, and `include_inactive` is the flag that makes an
/// un-callable instance visible at all.
fn finish_setup_steps() -> Vec<SetupStep> {
    vec![SetupStep {
        action: "get_service",
        params: serde_json::Map::from_iter([(
            "include_inactive".to_string(),
            serde_json::Value::Bool(true),
        )]),
        note: Some(
            "you already have an instance of this template awaiting setup — do not create \
             another, it will collide on the name. Pass its `name`. While `status` is \
             `pending_setup` its credential has not been proven to work: hand the setup URL \
             to your user. If that link expired unused, mint a fresh one with \
             `request_secret` passing the instance's `service_id`; if it was used and the \
             credential was wrong, the same call is refused with `secret_name_conflict` \
             because the value is already stored, so add `force: true` to replace it. It \
             becomes callable, and visible to search, once the credential checks out",
        ),
    }]
}

/// The ordered calls that take an un-connected template to a callable
/// instance.
///
/// One step, for both auth kinds: `create_service` mints whichever credential
/// handshake the template implies and returns it on the response —
/// `connect.auth_url` for OAuth, `setup.setup_url` for a secret. The `note` is
/// load-bearing, since it names the field the URL arrives on.
fn build_setup_steps(def: &ServiceDefinition) -> Vec<SetupStep> {
    let note = match def.auth.first() {
        Some(ServiceAuth::OAuth { .. }) => {
            // Hedged for the same reason as the secret arm below:
            // `want_auto_connect` needs an owner, so an org-level create gets
            // no bundle, and a failed connect is swallowed into a warning.
            "pick any `name`; it becomes the `service` you call afterwards. \
             Hand the returned `connect.auth_url` to your user verbatim. If \
             the response carries no `connect`, start the flow with \
             `create_connection` passing the new `service_id`"
        }
        Some(ServiceAuth::Secret { .. }) => {
            // Hedged on purpose. `create_service` attaches `setup` only for an
            // instance with an owner and an unbound slot, and drops the bundle
            // on a mint failure — so an org-level create (`user_level: false`)
            // reaches this step and gets no URL. Naming the fallback here is
            // what keeps that from being a dead end.
            "pick any `name`; it becomes the `service` you call afterwards. \
             Hand the returned `setup.setup_url` to your user verbatim — they \
             sign in, paste the credential there, and you never see it. If the \
             response carries no `setup`, mint one with `request_secret` \
             passing the new `service_id`. The instance comes back \
             `status: pending_setup` and is not callable until the credential \
             has been checked against the upstream, which happens when your \
             user submits it; wait for the `service.activated` event, or poll \
             `get_service` with `include_inactive` until `status` is `active`"
        }
        // No auth declared: nothing to provision, the instance is callable as
        // soon as it exists.
        None => "pick any `name`; it becomes the `service` you call afterwards",
    };

    vec![SetupStep {
        action: "create_service",
        params: serde_json::Map::from_iter([(
            "template_key".to_string(),
            serde_json::Value::String(def.key.clone()),
        )]),
        note: Some(note),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use overslash_core::types::service::{SecretSlot, TokenInjection};
    use overslash_core::types::{Runtime, SecretSource};
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

    fn def(auth: Vec<ServiceAuth>, secrets: Vec<SecretSlot>) -> ServiceDefinition {
        ServiceDefinition {
            default_additional_properties: false,
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

    /// The common shape: one implicit slot named after the scheme. The hint
    /// is one step — `create_service` mints the setup link itself.
    #[test]
    fn single_slot_secret_template_asks_for_one_step() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            Vec::new(),
        );
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "create_service");
        assert_eq!(steps[0].params["template_key"], "acme");
        assert!(
            steps[0].note.unwrap().contains("setup.setup_url"),
            "the secret note must name the field the URL arrives on"
        );
    }

    /// The hint stays one step however many slots the template declares:
    /// `create_service` mints one link per unbound slot and returns them
    /// together. No shipped template has two, which is exactly why this is a
    /// unit test — an assertion over the live catalog would pass vacuously.
    #[test]
    fn multi_slot_secret_template_still_asks_once() {
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
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 1, "one call, however many slots");
        assert_eq!(steps[0].action, "create_service");
        assert!(
            !steps.iter().any(|s| s.action == "request_secret"),
            "request_secret is no longer part of the happy path"
        );
    }

    #[test]
    fn oauth_template_points_at_the_connect_bundle() {
        let d = def(
            vec![ServiceAuth::OAuth {
                provider: "google".into(),
                scopes: vec!["calendar.readonly".into()],
                token_injection: injection(),
            }],
            Vec::new(),
        );
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "create_service");
        assert!(
            steps[0].note.unwrap().contains("connect.auth_url"),
            "the OAuth note must name the field the URL arrives on"
        );
        assert!(
            !steps.iter().any(|s| s.action == "create_connection"),
            "create_service auto-initiates the flow"
        );
    }

    #[test]
    fn authless_template_only_needs_create_service() {
        let d = def(Vec::new(), Vec::new());
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "create_service");
    }

    /// A gated instance is invisible to search *by design* — it is not
    /// callable — so the row the caller sees falls back to the catalog one.
    /// Left alone, that row's chain says `create_service`, which collides on
    /// the unique name index: the index knows nothing about lifecycle status.
    /// The whole point of the third state is to not send an agent into a 409.
    #[test]
    fn a_template_awaiting_setup_says_finish_it_rather_than_create_another() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            vec![slot("token", "acme_api_key", SecretSource::Instance)],
        );
        let status = build_auth_status(&d, false, true);

        assert!(!status.connected, "not callable, so still not connected");
        let steps = status.setup.expect("an un-connected row carries a chain");
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].action, "get_service",
            "never `create_service` — that is the 409"
        );
        assert_eq!(
            steps[0].params.get("include_inactive"),
            Some(&serde_json::Value::Bool(true)),
            "without this the instance 404s and looks like it was never created"
        );
        let note = steps[0].note.expect("the note is the load-bearing half");
        assert!(note.contains("do not create"), "{note}");
        assert!(note.contains("pending_setup"), "{note}");
    }

    /// …and the same template with nothing outstanding keeps the ordinary
    /// chain. The third state must not leak into the common case.
    #[test]
    fn a_template_with_no_gated_instance_keeps_the_create_chain() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            vec![slot("token", "acme_api_key", SecretSource::Instance)],
        );
        let steps = build_auth_status(&d, false, false).setup.unwrap();
        assert_eq!(steps[0].action, "create_service");
    }
}
