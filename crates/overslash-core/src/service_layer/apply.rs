//! The `apply()` half of the fold — overlay a [`Delta`] onto a resolved base.

use std::collections::HashSet;

use crate::template_validation::{Issues, ValidationIssue};
use crate::types::{Runtime, ServiceAction, ServiceDefinition};

use super::compile_extension_actions;
use super::types::{ActionPatch, Delta};

/// The `apply()` half of the fold: overlay `delta` onto an already-resolved
/// base, producing the effective [`ServiceDefinition`] plus non-blocking
/// **resolution warnings** (`shadowed_extension`, `dead_*`, `unreviewed_new_actions`).
///
/// The effective def keeps `base.key`; the async walker overrides it with the
/// deriving layer's own key (so a distinct-key layer surfaces under its own key,
/// a same-key layer keeps shadowing the base).
pub fn apply_delta(
    delta: &Delta,
    base: &ServiceDefinition,
) -> (ServiceDefinition, Vec<ValidationIssue>) {
    let mut issues = Issues::default();
    let mut actions = base.actions.clone();

    // ── Visibility = base.actions ∩ allowlist \ denylist ──────────────────
    if let Some(allow) = &delta.allowlist {
        let allow_set: HashSet<&str> = allow.iter().map(String::as_str).collect();
        for a in allow {
            if !base.actions.contains_key(a) {
                issues.warn(
                    "dead_allowlist_entry",
                    format!("allowlist entry '{a}' is not an action of the base template"),
                    format!("allowlist.{a}"),
                );
            }
        }
        actions.retain(|k, _| allow_set.contains(k.as_str()));

        // Autodiscover-safety: an allowlist over an autodiscovered MCP base
        // silently excludes any tool the upstream server adds later. Surface
        // the count so an admin can review + allowlist deliberately.
        if base.runtime == Runtime::Mcp && base.mcp.as_ref().is_some_and(|m| m.autodiscover) {
            let n = base
                .actions
                .keys()
                .filter(|k| !allow_set.contains(k.as_str()))
                .count();
            if n > 0 {
                issues.warn(
                    "unreviewed_new_actions",
                    format!("{n} action(s) on the autodiscovered base are not in the allowlist"),
                    "allowlist",
                );
            }
        }
    }
    for d in &delta.denylist {
        if !base.actions.contains_key(d) {
            issues.warn(
                "dead_denylist_entry",
                format!("denylist entry '{d}' is not an action of the base template"),
                format!("denylist.{d}"),
            );
        }
        actions.remove(d);
    }

    // ── action_patch: risk clamp-up / additive disclose / relabel ─────────
    for (key, patch) in &delta.action_patch {
        match actions.get_mut(key) {
            Some(action) => apply_action_patch(action, patch),
            None => {
                let reason = if base.actions.contains_key(key) {
                    "is masked out by allowlist/denylist"
                } else {
                    "is not an action of the base template"
                };
                issues.warn(
                    "dead_action_patch_target",
                    format!("action_patch target '{key}' {reason}"),
                    format!("action_patch.{key}"),
                );
            }
        }
    }

    // ── extensions: add new actions (base wins on collision) + hosts ──────
    let mut hosts = base.hosts.clone();
    for h in &delta.extensions.hosts {
        if !hosts.contains(h) {
            hosts.push(h.clone());
        }
    }

    // ── instance defaults: merge over the base's ──────────────────────────
    let instance_defaults = match &delta.instance_defaults {
        Some(d) => Some(d.merge_over(base.instance_defaults.as_ref())),
        None => base.instance_defaults.clone(),
    };
    // A default URL is also an egress target: the service+HTTP-verb shape
    // validates a caller-supplied `url:` against `hosts`, so without this union
    // an org could route its actions through its own gateway yet be unable to
    // name that gateway in a raw verb call. Appended (not prepended) — `hosts`
    // ordering still belongs to the template; the endpoint is read from
    // `instance_defaults.url` directly, not from `hosts.first()`.
    //
    // The **origin** (`scheme://host[:port]`) is unioned, not the bare hostname
    // `url_to_host` would give: the verb shape matches host AND port, so a bare
    // entry would both reject the admin's own `:8443` gateway and quietly
    // allow-list `:443` on that host, which they never named.
    if let Some(origin) = instance_defaults
        .as_ref()
        .and_then(|d| d.url.as_deref())
        .and_then(url_to_origin)
        && !hosts.contains(&origin)
    {
        hosts.push(origin);
    }
    if !delta.extensions.actions.is_empty() {
        match compile_extension_actions(base, &delta.extensions) {
            Ok(compiled) => {
                for (key, action) in compiled {
                    if base.actions.contains_key(&key) {
                        // Runtime collision: the base action wins; the extension
                        // is shadowed but not deleted, and we flag it.
                        issues.warn(
                            "shadowed_extension",
                            format!(
                                "extension action '{key}' collides with a base action; base wins"
                            ),
                            format!("extensions.actions.{key}"),
                        );
                        continue;
                    }
                    actions.insert(key, action);
                }
            }
            Err(errs) => {
                for e in errs {
                    issues.warn(
                        "extension_compile_failed",
                        format!("extension actions failed to compile: {}", e.message),
                        "extensions.actions",
                    );
                }
            }
        }
    }

    let def = ServiceDefinition {
        key: base.key.clone(),
        display_name: delta
            .display_name
            .clone()
            .unwrap_or_else(|| base.display_name.clone()),
        description: delta
            .description
            .clone()
            .or_else(|| base.description.clone()),
        hosts,
        category: base.category.clone(),
        hidden: delta.hidden.unwrap_or(base.hidden),
        auth: base.auth.clone(),
        // Credential slots ride with `auth`: a mask may add actions and hosts,
        // never rebind credentials.
        secrets: base.secrets.clone(),
        // Same reasoning for the non-secret inputs those credentials read: a
        // layer presets their *values* through `instance_defaults.config`, it
        // never redeclares them.
        config: base.config.clone(),
        actions,
        runtime: base.runtime,
        mcp: base.mcp.clone(),
        instance_defaults,
    };

    let report = issues.finish();
    (def, report.warnings)
}

fn apply_action_patch(action: &mut ServiceAction, patch: &ActionPatch) {
    if let Some(risk) = patch.risk {
        // Clamp UP only: raise to `risk` if it's more severe; never lower.
        // A `dynamic` base counts as write here ("write until proven read"),
        // so a mask pinning `write` (or `delete`) replaces the dynamism with
        // a static class — more approvals, never fewer.
        if risk.severity() >= action.risk.display_risk().severity() {
            action.risk = risk.into();
        }
    }
    if !patch.disclose.is_empty() {
        action.disclose.extend(patch.disclose.iter().cloned());
    }
    if let Some(desc) = &patch.description {
        action.description = desc.clone();
    }
}

/// The `scheme://host[:port]` prefix of a default endpoint, dropping any path.
/// Used to union the endpoint into `hosts` in a form the verb shape's
/// host-and-port matcher reads exactly — `url_to_host` would drop the port.
/// Returns `None` for anything `check_default_url` would reject.
fn url_to_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url
        .strip_prefix("https://")
        .map(|r| ("https", r))
        .or_else(|| url.strip_prefix("http://").map(|r| ("http", r)))?;
    let authority = rest.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_layer::fixtures::*;
    use crate::service_layer::{ExtensionAction, Extensions, validate_delta};
    use crate::types::Risk;
    use std::collections::HashMap;

    #[test]
    fn allowlist_intersects() {
        let base = base_with(&[("a", Risk::Read), ("b", Risk::Read), ("c", Risk::Write)]);
        let delta = Delta {
            allowlist: Some(vec!["a".into(), "b".into()]),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(keyset(&def), HashSet::from(["a".into(), "b".into()]));
    }

    #[test]
    fn empty_allowlist_exposes_nothing() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            allowlist: Some(vec![]),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert!(def.actions.is_empty());
    }

    #[test]
    fn denylist_removes() {
        let base = base_with(&[("a", Risk::Read), ("delete_repo", Risk::Delete)]);
        let delta = Delta {
            denylist: vec!["delete_repo".into()],
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(keyset(&def), HashSet::from(["a".into()]));
    }

    #[test]
    fn containment_child_subset_of_base() {
        // A chain: base → org (allow a,b,c) → user (allow a,b). The user layer
        // can never re-expose an action the org hid.
        let base = base_with(&[
            ("a", Risk::Read),
            ("b", Risk::Read),
            ("c", Risk::Read),
            ("d", Risk::Read),
        ]);
        let org_delta = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "c".into()]),
            ..Default::default()
        };
        let (org, _) = apply_delta(&org_delta, &base);
        // user tries to allow 'd' too — but folds over ORG, not base.
        let user_delta = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "d".into()]),
            ..Default::default()
        };
        let (user, _) = apply_delta(&user_delta, &org);
        assert!(keyset(&user).is_subset(&keyset(&org)));
        assert!(
            !user.actions.contains_key("d"),
            "user cannot re-expose 'd' hidden by org"
        );
        assert_eq!(keyset(&user), HashSet::from(["a".into(), "b".into()]));
    }

    #[test]
    fn masks_are_order_independent() {
        // S ∩ A₁\D₁ ∩ A₂\D₂ == S ∩ (A₁∩A₂) \ (D₁∪D₂)
        let base = base_with(&[
            ("a", Risk::Read),
            ("b", Risk::Read),
            ("c", Risk::Read),
            ("d", Risk::Read),
        ]);
        let d1 = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "c".into()]),
            denylist: vec!["c".into()],
            ..Default::default()
        };
        let d2 = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "d".into()]),
            denylist: vec!["b".into()],
            ..Default::default()
        };
        let (s1, _) = apply_delta(&d1, &base);
        let (s12, _) = apply_delta(&d2, &s1);
        let (s2, _) = apply_delta(&d2, &base);
        let (s21, _) = apply_delta(&d1, &s2);
        assert_eq!(keyset(&s12), keyset(&s21));
        assert_eq!(keyset(&s12), HashSet::from(["a".into()]));
    }

    #[test]
    fn risk_clamps_up_only() {
        let base = base_with(&[("merge", Risk::Write)]);
        // clamp up write→delete: applies
        let up = Delta {
            action_patch: HashMap::from([(
                "merge".to_string(),
                ActionPatch {
                    risk: Some(Risk::Delete),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let (def, _) = apply_delta(&up, &base);
        assert_eq!(def.actions["merge"].risk, Risk::Delete);

        // clamp down delete→write: ignored at apply
        let base2 = base_with(&[("merge", Risk::Delete)]);
        let down = Delta {
            action_patch: HashMap::from([(
                "merge".to_string(),
                ActionPatch {
                    risk: Some(Risk::Write),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let (def2, _) = apply_delta(&down, &base2);
        assert_eq!(
            def2.actions["merge"].risk,
            Risk::Delete,
            "clamp-down ignored"
        );
    }

    #[test]
    fn extension_adds_action_and_host() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            extensions: Extensions {
                actions: HashMap::from([(
                    "archive_repo".to_string(),
                    ExtensionAction {
                        method: "POST".into(),
                        path: "/repos/archive".into(),
                        operation: serde_json::json!({ "description": "Archive", "x-overslash-risk": "write" }),
                    },
                )]),
                hosts: vec!["ghe.acme.internal".into()],
            },
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(
            report.valid,
            "extension should validate: {:?}",
            report.errors
        );
        let (def, warnings) = apply_delta(&delta, &base);
        assert!(def.actions.contains_key("archive_repo"));
        assert!(def.hosts.contains(&"ghe.acme.internal".to_string()));
        assert_eq!(def.actions["archive_repo"].risk, Risk::Write);
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    }

    #[test]
    fn shadowed_extension_warns_base_wins() {
        // An extension whose key collides with a base key: apply keeps the base
        // (write-time validation would have rejected this, but at resolve time
        // an upstream base can grow a colliding key later).
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            extensions: Extensions {
                actions: HashMap::from([(
                    "a".to_string(),
                    ExtensionAction {
                        method: "POST".into(),
                        path: "/a".into(),
                        operation: serde_json::json!({ "description": "shadow" }),
                    },
                )]),
                hosts: vec![],
            },
            ..Default::default()
        };
        let (def, warnings) = apply_delta(&delta, &base);
        assert_eq!(def.actions["a"].method, "GET", "base action wins");
        assert!(warnings.iter().any(|w| w.code == "shadowed_extension"));
    }

    #[test]
    fn template_relabel_and_hide() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            display_name: Some("GitHub (Acme)".into()),
            hidden: Some(true),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(def.display_name, "GitHub (Acme)");
        assert!(def.hidden);
        assert_eq!(
            def.key, "github",
            "effective key stays the base key (walker overrides for distinct-key layers)"
        );
    }

    #[test]
    fn dead_entries_warn() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            allowlist: Some(vec!["a".into(), "nope".into()]),
            ..Default::default()
        };
        let (_, warnings) = apply_delta(&delta, &base);
        assert!(warnings.iter().any(|w| w.code == "dead_allowlist_entry"));
    }

    // ── instance_defaults ────────────────────────────────────────────────

    /// A credential template's non-secret input is defaultable by a layer for
    /// free, because it is a key of the same `config` map — an org sets its
    /// shared mailbox login once instead of every user retyping it. This is why
    /// `Delta` needs no second config field.
    #[test]
    fn instance_defaults_may_target_a_credential_config_var() {
        let mut base = base_with(&[("a", Risk::Read)]);
        base.config = vec![crate::types::ConfigVar {
            key: "mailbox_user".into(),
            label: "Mailbox username".into(),
            description: String::new(),
            required: true,
            identity: false,
        }];
        let delta = Delta {
            instance_defaults: Some(defaults(None, &[("mailbox_user", "ops@acme.com")])),
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(report.valid, "got errors: {:?}", report.errors);

        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(
            def.instance_defaults.unwrap().config.get("mailbox_user"),
            Some(&"ops@acme.com".to_string())
        );
        // The declaration itself is the base's, untouched: a layer supplies a
        // value, never a relabel — and never a credential.
        assert_eq!(def.config[0].label, "Mailbox username");
        assert!(def.config[0].required);
        assert_eq!(def.secrets.len(), base.secrets.len());
    }

    #[test]
    fn instance_defaults_url_sets_effective_endpoint() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://ghe.acme.internal"), &[])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(
            def.instance_defaults.unwrap().url.unwrap(),
            "https://ghe.acme.internal"
        );
        assert_eq!(
            def.hosts[0], "api.github.com",
            "the template still owns `hosts` ordering; the endpoint is read from instance_defaults"
        );
    }

    #[test]
    fn defaults_url_trailing_slash_is_normalized() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://ghe.acme.internal/"), &[])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(
            def.instance_defaults.unwrap().url.unwrap(),
            "https://ghe.acme.internal",
            "otherwise `format!(\"{{base}}{{path}}\")` yields a double slash"
        );
    }

    #[test]
    fn defaults_origin_unioned_into_hosts_with_port() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://ghe.acme.internal:8443/api"), &[])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert!(
            def.hosts
                .contains(&"https://ghe.acme.internal:8443".to_string()),
            "the default endpoint must be a legal egress target for the service \
             + HTTP-verb shape, which matches host AND port — a bare hostname \
             would reject :8443 and silently allow :443. got {:?}",
            def.hosts
        );
        assert!(
            !def.hosts.contains(&"ghe.acme.internal".to_string()),
            "the bare-hostname form must not leak in: it implies :443"
        );
    }

    #[test]
    fn defaults_override_through_an_org_layer_chain() {
        // Only org layers may *set* defaults, so the override case is an org
        // layer over an org layer: gateway + pin, then a re-point of the pin.
        let base = base_with_pinnable_param("X-Imap");
        let outer = Delta {
            instance_defaults: Some(defaults(
                Some("https://mail.overfolder-dev.com"),
                &[("X-Imap", "imap.acme.com")],
            )),
            ..Default::default()
        };
        let (outer_def, _) = apply_delta(&outer, &base);

        let inner = Delta {
            instance_defaults: Some(defaults(None, &[("X-Imap", "imap.eu.acme.com")])),
            ..Default::default()
        };
        let (inner_def, _) = apply_delta(&inner, &outer_def);

        let d = inner_def.instance_defaults.unwrap();
        assert_eq!(
            d.url.unwrap(),
            "https://mail.overfolder-dev.com",
            "a layer that does not re-point inherits the gateway"
        );
        assert_eq!(d.config["X-Imap"], "imap.eu.acme.com");
    }

    #[test]
    fn user_layer_inherits_org_defaults_untouched() {
        // A user layer may not *set* defaults, but it must still *inherit* them
        // — otherwise a user's own curation of an org template would silently
        // drop the org's gateway.
        let base = base_with_pinnable_param("X-Imap");
        let org = Delta {
            instance_defaults: Some(defaults(
                Some("https://mail.overfolder-dev.com"),
                &[("X-Imap", "imap.acme.com")],
            )),
            ..Default::default()
        };
        let (org_def, _) = apply_delta(&org, &base);

        let user = Delta {
            denylist: vec!["a".into()],
            ..Default::default()
        };
        assert!(
            validate_delta(&user, &org_def, true).valid,
            "a user layer with no instance_defaults of its own is legal"
        );
        let (user_def, _) = apply_delta(&user, &org_def);
        assert_eq!(
            user_def.instance_defaults.unwrap(),
            org_def.instance_defaults.unwrap()
        );
    }

    #[test]
    fn config_defaults_are_trimmed_at_fold_time() {
        // Symmetric with the instance write path, which trims on write — the
        // same value must inject byte-identically from either source.
        let base = base_with_pinnable_param("X-Imap");
        let delta = Delta {
            instance_defaults: Some(defaults(None, &[("X-Imap", "  imap.acme.com  ")])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(
            def.instance_defaults.unwrap().config["X-Imap"],
            "imap.acme.com"
        );
    }

    #[test]
    fn defaults_inherit_when_child_delta_has_none() {
        let base = base_with(&[("a", Risk::Read)]);
        let org = Delta {
            instance_defaults: Some(defaults(Some("https://gw.acme.com"), &[])),
            ..Default::default()
        };
        let (org_def, _) = apply_delta(&org, &base);
        let (child_def, _) = apply_delta(&Delta::default(), &org_def);
        assert_eq!(
            child_def.instance_defaults.unwrap().url.unwrap(),
            "https://gw.acme.com"
        );
    }
}
