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

pub(super) fn build_auth_status(def: &ServiceDefinition, connected: bool) -> AuthStatus {
    // Pick the first declared auth method as the primary face the caller
    // sees. Templates that mix auth methods (rare) still surface here with
    // the preferred one first — exactly how the dashboard displays them.
    let (kind, provider) = match def.auth.first() {
        Some(ServiceAuth::OAuth { provider, .. }) => ("oauth".into(), Some(provider.clone())),
        Some(ServiceAuth::Secret { .. }) => ("secret".into(), None),
        None => ("none".into(), None),
    };
    let setup = (!connected).then(|| build_setup_steps(def));
    AuthStatus {
        kind,
        provider,
        connected,
        setup,
    }
}

/// The ordered calls that take an un-connected template to a callable
/// instance.
///
/// One step, for both auth kinds: `create_service` mints whichever credential
/// handshake the template implies and returns it on the response —
/// `connect.auth_url` for OAuth, `setup.setup_url` for a secret. Until that
/// landed this emitted a second `request_secret` step per credential slot, and
/// an agent following it made two calls and handed its user a link that named
/// a vault key rather than the service it was for.
fn build_setup_steps(def: &ServiceDefinition) -> Vec<SetupStep> {
    let note = match def.auth.first() {
        Some(ServiceAuth::OAuth { .. }) => {
            "pick any `name`; it becomes the `service` you call afterwards. \
             Hand the returned `connect.auth_url` to your user verbatim"
        }
        Some(ServiceAuth::Secret { .. }) => {
            "pick any `name`; it becomes the `service` you call afterwards. \
             Hand the returned `setup.setup_url` to your user verbatim — they \
             paste the credential there and you never see it"
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

    /// Regression, inverted. This used to emit one `request_secret` step per
    /// slot — and an earlier cut emitted a single step whose `secret_name` was
    /// an array, which would have deserialize-failed the moment an agent
    /// followed it. Both are moot: `create_service` mints one link per unbound
    /// slot and returns them together, so the hint stays one step however many
    /// slots the template declares. No shipped template has two, which is
    /// exactly why this is a unit test.
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
}
