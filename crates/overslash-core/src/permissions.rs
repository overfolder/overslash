use std::collections::HashMap;

use crate::types::{PermissionEffect, PermissionRule};

/// A derived permission key from an action request.
///
/// Two formats depending on execution mode:
/// - Raw HTTP / connection: `http:{METHOD}:{host}{path}`
/// - Service action (Mode C): `{service}:{action}:{arg}`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionKey(pub String);

impl PermissionKey {
    /// Derive permission keys from an HTTP request (Mode A / Mode B).
    /// Format: `http:{METHOD}:{host}{path}`
    pub fn from_http(method: &str, url: &str) -> Vec<Self> {
        let host_path = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        vec![Self(format!("http:{method}:{host_path}"))]
    }

    /// Derive permission keys from a service action request (Mode C).
    /// Format: `{service}:{action}:{arg}` where arg comes from `scope_param` or defaults to `*`.
    pub fn from_service_action(
        service_key: &str,
        action_key: &str,
        scope_param: Option<&str>,
        params: &HashMap<String, serde_json::Value>,
    ) -> Vec<Self> {
        let arg = scope_param
            .and_then(|sp| params.get(sp))
            .map(|v| match v.as_str() {
                Some(s) => s.to_string(),
                None => v.to_string(),
            })
            .unwrap_or_else(|| "*".to_string());
        vec![Self(format!("{service_key}:{action_key}:{arg}"))]
    }
}

/// Result of checking permissions against rules.
#[derive(Debug, PartialEq, Eq)]
pub enum PermissionResult {
    /// All keys are covered by allow rules.
    Allowed,
    /// Some keys need approval.
    NeedsApproval(Vec<PermissionKey>),
    /// Explicitly denied by a deny rule.
    Denied(String),
}

/// Check whether the given permission keys are authorized by the rules.
///
/// Rules are evaluated in order: deny rules override allow rules.
/// All keys must be covered by allow rules for the result to be `Allowed`.
pub fn check_permissions(rules: &[PermissionRule], keys: &[PermissionKey]) -> PermissionResult {
    // First check for explicit denies
    for key in keys {
        for rule in rules {
            if rule.effect == PermissionEffect::Deny
                && glob_match::glob_match(&rule.action_pattern, &key.0)
            {
                return PermissionResult::Denied(format!(
                    "denied by rule: {}",
                    rule.action_pattern
                ));
            }
        }
    }

    // Then check for allows
    let mut uncovered = Vec::new();
    for key in keys {
        let covered = rules.iter().any(|rule| {
            rule.effect == PermissionEffect::Allow
                && glob_match::glob_match(&rule.action_pattern, &key.0)
        });
        if !covered {
            uncovered.push(key.clone());
        }
    }

    if uncovered.is_empty() {
        PermissionResult::Allowed
    } else {
        PermissionResult::NeedsApproval(uncovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn rule(pattern: &str, effect: PermissionEffect) -> PermissionRule {
        PermissionRule {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            action_pattern: pattern.to_string(),
            effect,
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn exact_match_allows() {
        let rules = vec![rule(
            "http:POST:api.stripe.com/v1/charges",
            PermissionEffect::Allow,
        )];
        let keys = vec![PermissionKey("http:POST:api.stripe.com/v1/charges".into())];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    #[test]
    fn wildcard_match_allows() {
        let rules = vec![rule("http:POST:api.stripe.com/**", PermissionEffect::Allow)];
        let keys = vec![PermissionKey("http:POST:api.stripe.com/v1/charges".into())];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    #[test]
    fn no_rules_needs_approval() {
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        assert!(matches!(
            check_permissions(&[], &keys),
            PermissionResult::NeedsApproval(_)
        ));
    }

    #[test]
    fn deny_overrides_allow() {
        let rules = vec![
            rule("http:*:api.stripe.com/**", PermissionEffect::Allow),
            rule("http:DELETE:api.stripe.com/**", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "http:DELETE:api.stripe.com/v1/charges/ch_123".into(),
        )];
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::Denied(_)
        ));
    }

    #[test]
    fn partial_coverage_needs_approval() {
        let rules = vec![rule("http:GET:api.github.com/**", PermissionEffect::Allow)];
        let keys = vec![
            PermissionKey("http:GET:api.github.com/repos".into()),
            PermissionKey("http:POST:api.github.com/repos/x/pulls".into()),
        ];
        match check_permissions(&rules, &keys) {
            PermissionResult::NeedsApproval(uncovered) => {
                assert_eq!(uncovered.len(), 1);
                assert_eq!(uncovered[0].0, "http:POST:api.github.com/repos/x/pulls");
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn empty_keys_always_allowed() {
        assert_eq!(check_permissions(&[], &[]), PermissionResult::Allowed);
    }

    #[test]
    fn derive_keys_from_http() {
        let keys = PermissionKey::from_http("POST", "https://api.github.com/repos/x/pulls");
        assert_eq!(keys[0].0, "http:POST:api.github.com/repos/x/pulls");
    }

    #[test]
    fn service_action_with_scope_param() {
        let mut params = HashMap::new();
        params.insert(
            "repo".to_string(),
            serde_json::Value::String("overfolder/backend".to_string()),
        );
        let keys = PermissionKey::from_service_action(
            "github",
            "create_pull_request",
            Some("repo"),
            &params,
        );
        assert_eq!(keys[0].0, "github:create_pull_request:overfolder/backend");
    }

    #[test]
    fn service_action_scope_param_missing_value() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action(
            "github",
            "create_pull_request",
            Some("repo"),
            &params,
        );
        assert_eq!(keys[0].0, "github:create_pull_request:*");
    }

    #[test]
    fn service_action_no_scope_param() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action("github", "list_repos", None, &params);
        assert_eq!(keys[0].0, "github:list_repos:*");
    }

    #[test]
    fn glob_matches_service_action_keys() {
        let rules = vec![rule("github:*:overfolder/*", PermissionEffect::Allow)];
        let keys = vec![PermissionKey(
            "github:create_pull_request:overfolder/backend".into(),
        )];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    #[test]
    fn service_action_deny_specific_scope() {
        let rules = vec![
            rule("github:*:*", PermissionEffect::Allow),
            rule("github:*:overfolder/secret-repo", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "github:create_issue:overfolder/secret-repo".into(),
        )];
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::Denied(_)
        ));
    }
}
