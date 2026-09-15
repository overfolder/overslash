//! How a search row advertises what it still needs to become callable.
//!
//! A row that names a service the caller cannot use yet is only half an
//! answer. `AuthStatus` carries the diagnosis (`type`, `connected`) and, when
//! the row is not callable, `setup`: the ordered platform calls that fix it.
//! Agents read this at exactly the moment they discover the gap, so it is the
//! difference between self-service and handing the job back to a human.

use serde::Serialize;

use overslash_core::types::{SecretSource, ServiceAuth, ServiceDefinition};

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
/// instance: always `create_service`, then whichever credential step the
/// template's auth implies.
fn build_setup_steps(def: &ServiceDefinition) -> Vec<SetupStep> {
    let mut steps = vec![SetupStep {
        action: "create_service",
        params: serde_json::Map::from_iter([(
            "template_key".to_string(),
            serde_json::Value::String(def.key.clone()),
        )]),
        note: Some("pick any `name`; it becomes the `service` you call afterwards"),
    }];

    match def.auth.first() {
        Some(ServiceAuth::OAuth { provider, .. }) => steps.push(SetupStep {
            action: "create_connection",
            params: serde_json::Map::from_iter([(
                "provider".to_string(),
                serde_json::Value::String(provider.clone()),
            )]),
            note: Some("hand the returned `auth_url` to your user verbatim"),
        }),
        Some(ServiceAuth::Secret { .. }) => {
            // Which vault names to ask for. The instance-source slots are the
            // ones an operator binds per instance — `slots_for` owns that
            // rule, so read it rather than re-deriving from the auth entry.
            //
            // One step per slot, never one step naming several: `request_secret`
            // declares `secret_name` as a `string` (services/overslash.yaml), so
            // an array there would deserialize-fail the moment an agent followed
            // the instruction — a setup hint that breaks the setup. A template
            // with two slots therefore gets two `request_secret` steps, and the
            // agent hands its user one provide URL per secret.
            // The emptiness guard is on `default_secret_name`, the field this
            // step actually pre-fills — not on `key`, which is what
            // `reconcile::instance_slot_keys` guards because *it* keys a
            // binding by it. An instance-source slot with no default name is a
            // deliberately supported shape (`template_validation::core::auth`
            // requires a default only for org-source slots, since an instance
            // slot resolves from the instance's own binding), so this is a
            // real template, not a malformed one. There is simply no name to
            // pre-fill for it, and `secret_name: ""` is worse than no step:
            // `kernel_request_secret` rejects a blank name with a 400, so the
            // hint would break the setup it describes. Such a slot still
            // surfaces at call time, by name, in `credential_missing`'s
            // `missing_credentials` + `self_serve`.
            for slot in def
                .all_slots()
                .into_iter()
                .filter(|s| s.source == SecretSource::Instance && !s.default_secret_name.is_empty())
            {
                steps.push(SetupStep {
                    action: "request_secret",
                    params: serde_json::Map::from_iter([(
                        "secret_name".to_string(),
                        serde_json::Value::String(slot.default_secret_name.clone()),
                    )]),
                    note: Some(
                        "hand the returned `provide_url` to your user — you never see the value",
                    ),
                });
            }
        }
        None => {}
    }

    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use overslash_core::types::Runtime;
    use overslash_core::types::service::{SecretSlot, TokenInjection};
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

    /// The common shape: one implicit slot named after the scheme.
    #[test]
    fn single_slot_secret_template_asks_for_one_secret() {
        let d = def(
            vec![secret_auth("token", "acme_api_key", Vec::new())],
            Vec::new(),
        );
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].action, "create_service");
        assert_eq!(steps[1].action, "request_secret");
        assert_eq!(steps[1].params["secret_name"], "acme_api_key");
    }

    /// Regression: a template with two instance-source slots must produce two
    /// `request_secret` steps, each naming one secret as a **string**.
    ///
    /// The first cut emitted a single step whose `secret_name` was an array.
    /// `request_secret` declares that param as `string`, so an agent following
    /// the hint would have failed deserialization — a setup instruction that
    /// breaks the setup it describes. No shipped template currently declares
    /// two instance slots, which is exactly why this is a unit test: the
    /// integration assertion over the live catalog would pass vacuously.
    #[test]
    fn multi_slot_secret_template_asks_once_per_secret() {
        let d = def(
            vec![secret_auth(
                "mailbox",
                "unused_fallback",
                vec!["mailbox_user".into(), "mailbox_pass".into()],
            )],
            vec![
                slot("mailbox_user", "acme_user", SecretSource::Instance),
                slot("mailbox_pass", "acme_pass", SecretSource::Instance),
            ],
        );
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 3, "create_service + one step per slot");
        let secret_steps: Vec<_> = steps
            .iter()
            .filter(|s| s.action == "request_secret")
            .collect();
        assert_eq!(secret_steps.len(), 2);
        for step in &secret_steps {
            assert!(
                step.params["secret_name"].is_string(),
                "secret_name must be a string, got {:?}",
                step.params["secret_name"]
            );
        }
        assert_eq!(secret_steps[0].params["secret_name"], "acme_user");
        assert_eq!(secret_steps[1].params["secret_name"], "acme_pass");
    }

    /// An instance-source slot may legitimately declare no `default_secret_name`
    /// — validation only requires one for org-source slots. There is no name to
    /// pre-fill, and `secret_name: ""` would 400 in `kernel_request_secret`, so
    /// the step is omitted rather than emitted broken.
    #[test]
    fn instance_slot_without_a_default_name_yields_no_request_step() {
        let d = def(
            vec![secret_auth(
                "acme",
                "unused_fallback",
                vec!["named".into(), "unnamed".into()],
            )],
            vec![
                slot("named", "acme_key", SecretSource::Instance),
                slot("unnamed", "", SecretSource::Instance),
            ],
        );
        let steps = build_setup_steps(&d);

        let secret_steps: Vec<_> = steps
            .iter()
            .filter(|s| s.action == "request_secret")
            .collect();
        assert_eq!(secret_steps.len(), 1, "only the named slot is requestable");
        assert_eq!(secret_steps[0].params["secret_name"], "acme_key");
    }

    /// Org-source slots are the deployment's to set, not the caller's, so they
    /// are not something to ask this user for.
    #[test]
    fn org_source_slots_are_not_requested() {
        let d = def(
            vec![secret_auth(
                "gateway",
                "unused_fallback",
                vec!["gateway_key".into(), "instance_key".into()],
            )],
            vec![
                slot("gateway_key", "shared_gateway_key", SecretSource::Org),
                slot("instance_key", "acme_key", SecretSource::Instance),
            ],
        );
        let steps = build_setup_steps(&d);

        let secret_steps: Vec<_> = steps
            .iter()
            .filter(|s| s.action == "request_secret")
            .collect();
        assert_eq!(secret_steps.len(), 1);
        assert_eq!(secret_steps[0].params["secret_name"], "acme_key");
    }

    #[test]
    fn oauth_template_asks_for_a_connection_not_a_secret() {
        let d = def(
            vec![ServiceAuth::OAuth {
                provider: "google".into(),
                scopes: Vec::new(),
                token_injection: injection(),
            }],
            Vec::new(),
        );
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[1].action, "create_connection");
        assert_eq!(steps[1].params["provider"], "google");
    }

    /// A template needing no credential is callable the moment the instance
    /// exists, so there is no second step to offer.
    #[test]
    fn authless_template_only_needs_create_service() {
        let d = def(Vec::new(), Vec::new());
        let steps = build_setup_steps(&d);

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "create_service");
    }
}
