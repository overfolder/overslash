//! Write-time validation of a [`Delta`] against its resolved base.

use std::collections::HashSet;

use crate::instance_config;
use crate::template_validation::{Issues, ValidationReport};
use crate::types::ServiceDefinition;

use super::apply::apply_delta;
use super::compile_extension_actions;
use super::types::Delta;

/// Write-time **blocking** validation of a delta against its resolved base.
/// Returns a [`ValidationReport`] in the same shape as template validation.
///
/// `user_tier` is `true` when the layer being written is owned by an individual
/// (`service_templates.owner_identity_id IS NOT NULL`). It gates
/// [`InstanceDefaults`], which can redirect where an org's traffic lands and so
/// stays with org admins.
pub fn validate_delta(
    delta: &Delta,
    base: &ServiceDefinition,
    user_tier: bool,
) -> ValidationReport {
    let mut issues = Issues::default();

    // `display_name` and `description` need no checking — they are inert
    // strings. `icon` is not: it is the one delta field that becomes a URL the
    // operator's browser loads, so the standalone path's https-only rule has to
    // hold here too or the derived-layer write path is an unvalidated back door
    // into it.
    crate::template_validation::check_service_icon(delta.icon.as_ref(), "icon", &mut issues);

    // The base's FULL keyset (there is no hidden-vs-visible split once compiled;
    // every base action key is off-limits for an extension).
    let base_keys: HashSet<&str> = base.actions.keys().map(String::as_str).collect();

    // allowlist / denylist entries should reference real base actions (a dead
    // entry is a warning at resolve time, but at write time we surface it too so
    // a typo is caught immediately — non-blocking).
    if let Some(allow) = &delta.allowlist {
        for a in allow {
            if !base_keys.contains(a.as_str()) {
                issues.warn(
                    "dead_allowlist_entry",
                    format!("allowlist entry '{a}' is not an action of the base template"),
                    format!("allowlist.{a}"),
                );
            }
        }
    }
    for d in &delta.denylist {
        if !base_keys.contains(d.as_str()) {
            issues.warn(
                "dead_denylist_entry",
                format!("denylist entry '{d}' is not an action of the base template"),
                format!("denylist.{d}"),
            );
        }
    }

    // action_patch: target must exist; risk may only clamp UP.
    for (key, patch) in &delta.action_patch {
        match base.actions.get(key) {
            None => issues.err(
                "unknown_action",
                format!("action_patch target '{key}' is not an action of the base template"),
                format!("action_patch.{key}"),
            ),
            Some(action) => {
                if let Some(risk) = patch.risk
                    && risk.severity() < action.risk.display_risk().severity()
                {
                    issues.err(
                        "risk_clamp_down",
                        format!(
                            "action_patch may only raise risk (base '{}' is '{}', patch '{}')",
                            key, action.risk, risk
                        ),
                        format!("action_patch.{key}.risk"),
                    );
                }
            }
        }
    }

    // extensions: keys must not collide with ANY base key (closes the
    // hide-then-re-add hijack); fragments must compile; no rebinding.
    for key in delta.extensions.actions.keys() {
        if base_keys.contains(key.as_str()) {
            issues.err(
                "extension_key_collision",
                format!(
                    "extension action '{key}' collides with a base action key \
                     (extensions may only add new keys, never rebind)"
                ),
                format!("extensions.actions.{key}"),
            );
        }
    }
    if !delta.extensions.actions.is_empty() {
        match compile_extension_actions(base, &delta.extensions) {
            // Write-time surfacing, so an extension operation declaring something
            // nothing reads is named while the author still has the delta open —
            // `POST /v1/templates/validate-delta` renders these in the layer
            // editor.
            Ok((_, lint_warnings)) => {
                for w in lint_warnings {
                    issues.warn(w.code, w.message, w.path);
                }
            }
            Err(errs) => {
                for e in errs {
                    issues.err(
                        "extension_invalid",
                        format!("extension actions failed to compile: {}", e.message),
                        "extensions.actions",
                    );
                }
            }
        }
    }

    // instance_defaults: org-tier only; a valid absolute endpoint; config keys
    // the template actually declares.
    //
    // The tier gate keys off *presence*, not content: accepting a
    // `"instance_defaults": {}` from a user layer would persist a field the
    // error text says is rejected outright.
    if let Some(defaults) = &delta.instance_defaults {
        if user_tier {
            issues.err(
                "instance_defaults_user_tier",
                "a user layer may not set `instance_defaults` — an endpoint or config default \
                 that every instance inherits is an org-admin decision"
                    .to_string(),
                "instance_defaults",
            );
        }
        if let Some(url) = &defaults.url
            && let Err(reason) = check_default_url(url)
        {
            issues.err(
                "instance_defaults_invalid_url",
                format!("`instance_defaults.url` {reason}"),
                "instance_defaults.url",
            );
        }
        // Validate config keys against the *folded* surface, not the base's:
        // this delta's own extension actions may declare instance-config params,
        // and defaulting one of those is legitimate.
        if !defaults.config.is_empty() {
            let (folded, _) = apply_delta(delta, base);
            if let Err(e) = instance_config::validate_config(&folded, &defaults.config) {
                issues.err(
                    e.code(),
                    e.message(&folded.key),
                    format!("instance_defaults.config.{}", e.key()),
                );
            }
        }
    }

    issues.finish()
}

/// Shape check for a layer's default endpoint. Deliberately string-level (core
/// carries no URL parser): an absolute `http`/`https` URL with a host and no
/// query or fragment. A path prefix is allowed — a gateway mounted under
/// `/api/v3` is a legitimate base — but a request is not.
fn check_default_url(url: &str) -> Result<(), &'static str> {
    let trimmed = url.trim();
    if trimmed != url {
        return Err("must not have leading or trailing whitespace");
    }
    let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
    else {
        return Err("must be an absolute URL starting with http:// or https://");
    };
    if rest.split('/').next().unwrap_or("").is_empty() {
        return Err("has no host");
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err("must not carry a query string or fragment");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_layer::fixtures::*;
    use crate::service_layer::{ActionPatch, ExtensionAction, Extensions, InstanceDefaults};
    use crate::types::Risk;
    use std::collections::HashMap;

    #[test]
    fn validate_rejects_a_non_https_delta_icon() {
        // The derived-layer write path must not be a way around the standalone
        // path's https-only rule.
        let base = base_with(&[("a", Risk::Read)]);
        for raw in ["javascript:alert(1)", "http://example.com/a.svg"] {
            let delta = Delta {
                icon: Some(crate::service_icon::ServiceIcon::try_from(raw.to_string()).unwrap()),
                ..Default::default()
            };
            let report = validate_delta(&delta, &base, false);
            assert!(!report.valid, "{raw} should be rejected");
            assert!(report.errors.iter().any(|e| e.code == "invalid_icon"));
        }
    }

    #[test]
    fn validate_accepts_an_https_delta_icon() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            icon: Some(
                crate::service_icon::ServiceIcon::try_from(
                    "https://cdn.acme.test/logo.svg".to_string(),
                )
                .unwrap(),
            ),
            ..Default::default()
        };
        assert!(validate_delta(&delta, &base, false).valid);
    }

    #[test]
    fn validate_rejects_risk_clamp_down() {
        let base = base_with(&[("merge", Risk::Delete)]);
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
        let report = validate_delta(&down, &base, false);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.code == "risk_clamp_down"));
    }

    #[test]
    fn validate_rejects_extension_collision_including_hidden() {
        // denylist hides delete_repo, then extensions re-adds it → rejected,
        // because collision is checked against the base's FULL keyset.
        let base = base_with(&[("delete_repo", Risk::Delete)]);
        let delta = Delta {
            denylist: vec!["delete_repo".into()],
            extensions: Extensions {
                actions: HashMap::from([(
                    "delete_repo".to_string(),
                    ExtensionAction {
                        method: "DELETE".into(),
                        path: "/x".into(),
                        operation: serde_json::json!({}),
                    },
                )]),
                hosts: vec![],
            },
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "extension_key_collision")
        );
    }

    // ── instance_defaults ────────────────────────────────────────────────

    #[test]
    fn empty_defaults_still_rejected_on_a_user_layer() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(InstanceDefaults::default()),
            ..Default::default()
        };
        assert!(
            !validate_delta(&delta, &base, true).valid,
            "presence, not content, gates the tier — otherwise the API persists \
             a field it claims to reject"
        );
    }

    #[test]
    fn defaults_rejected_for_user_tier() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://evil.example.com"), &[])),
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, true);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "instance_defaults_user_tier")
        );
        assert!(
            validate_delta(&delta, &base, false).valid,
            "the same delta is legal on an org layer"
        );
    }

    #[test]
    fn defaults_url_must_be_an_absolute_origin() {
        let base = base_with(&[("a", Risk::Read)]);
        for bad in [
            "ghe.acme.internal",
            "ftp://ghe.acme.internal",
            "https://",
            "https://gw.acme.com/x?a=1",
            "https://gw.acme.com#f",
        ] {
            let delta = Delta {
                instance_defaults: Some(defaults(Some(bad), &[])),
                ..Default::default()
            };
            let report = validate_delta(&delta, &base, false);
            assert!(
                report
                    .errors
                    .iter()
                    .any(|e| e.code == "instance_defaults_invalid_url"),
                "'{bad}' should be rejected"
            );
        }
    }

    #[test]
    fn undeclared_config_default_is_rejected() {
        let base = base_with_pinnable_param("X-Imap");
        let delta = Delta {
            instance_defaults: Some(defaults(None, &[("X-Nope", "v")])),
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "unknown_instance_config")
        );

        let ok = Delta {
            instance_defaults: Some(defaults(None, &[("X-Imap", "imap.acme.com")])),
            ..Default::default()
        };
        assert!(validate_delta(&ok, &base, false).valid);
    }

    #[test]
    fn config_default_may_target_this_deltas_own_extension_action() {
        // Regression guard on fold order: config keys validate against the
        // *folded* surface, so a param declared by an action this same delta
        // adds is defaultable. Validating against the bare base would 400.
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            extensions: Extensions {
                actions: HashMap::from([(
                    "regional".to_string(),
                    ExtensionAction {
                        method: "GET".into(),
                        path: "/regional".into(),
                        operation: serde_json::json!({
                            "description": "Regional lookup",
                            "x-overslash-risk": "read",
                            "parameters": [{
                                "name": "X-Region",
                                "in": "header",
                                "schema": { "type": "string" },
                                "x-overslash-instance-config": true
                            }]
                        }),
                    },
                )]),
                hosts: vec![],
            },
            instance_defaults: Some(defaults(None, &[("X-Region", "eu-west-1")])),
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(
            report.valid,
            "expected valid, got errors: {:?}",
            report.errors
        );
    }

    /// An extension operation goes through the same compile as a shipped
    /// template, so it inherits the same silent no-ops — `x-overslash-download`
    /// is MCP-only and does nothing on an HTTP operation.
    ///
    /// The finding's path must address the delta the author submitted, not the
    /// synthetic `paths./regional.get` document assembled to compile it.
    #[test]
    fn extension_action_declaring_an_ignored_key_warns_against_the_delta_path() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            extensions: Extensions {
                actions: HashMap::from([(
                    "regional".to_string(),
                    ExtensionAction {
                        method: "GET".into(),
                        path: "/regional".into(),
                        operation: serde_json::json!({
                            "description": "Regional lookup",
                            "x-overslash-risk": "read",
                            "x-overslash-download": { "url": ".url" },
                            "response_type": "binary"
                        }),
                    },
                )]),
                hosts: vec![],
            },
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(
            report.valid,
            "an ignored key must not block the delta: {:?}",
            report.errors
        );
        let paths: Vec<&str> = report.warnings.iter().map(|w| w.path.as_str()).collect();
        assert!(
            paths.contains(&"extensions.actions.regional.operation.x-overslash-download"),
            "download finding should address the delta, got {paths:?}"
        );
        assert!(
            paths.contains(&"extensions.actions.regional.operation.response_type"),
            "response_type finding should address the delta, got {paths:?}"
        );
    }
}
