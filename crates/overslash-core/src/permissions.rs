use std::collections::HashMap;
use uuid::Uuid;

use crate::types::{PermissionEffect, PermissionRule};

/// A derived permission key from an action request.
/// Format: `http:{METHOD}:{host}{path}`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionKey(pub String);

impl PermissionKey {
    /// Derive permission keys from an HTTP request.
    pub fn from_http(method: &str, url: &str) -> Vec<Self> {
        let host_path = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        vec![Self(format!("http:{method}:{host_path}"))]
    }
}

/// Result of checking permissions against rules (flat, single-identity).
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

// --- Hierarchical chain walk ---

/// An identity level in the chain, carrying just the fields needed for the walk.
#[derive(Debug, Clone)]
pub struct ChainIdentity {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub inherit_permissions: bool,
}

/// A gap detected during chain walk.
#[derive(Debug, Clone)]
pub struct PermissionGap {
    pub gap_identity_id: Uuid,
    pub gap_identity_name: String,
    pub uncovered_keys: Vec<PermissionKey>,
    pub can_be_handled_by: Vec<Uuid>,
}

/// Result of hierarchical permission resolution.
#[derive(Debug)]
pub enum ChainWalkResult {
    Allowed,
    NeedsApproval(Vec<PermissionGap>),
    Denied(String),
}

/// Walk the ancestor chain from leaf to root, checking permissions at each level.
///
/// `chain` must be ordered root-to-leaf (depth ascending).
/// `rules_by_identity` maps identity ID to that identity's active permission rules.
pub fn resolve_chain(
    chain: &[ChainIdentity],
    rules_by_identity: &HashMap<Uuid, Vec<PermissionRule>>,
    keys: &[PermissionKey],
) -> ChainWalkResult {
    if keys.is_empty() {
        return ChainWalkResult::Allowed;
    }

    let mut gaps = Vec::new();
    let empty_rules = Vec::new();

    // Walk from leaf (last) toward root (first)
    for (rev_idx, identity) in chain.iter().rev().enumerate() {
        let rules = rules_by_identity.get(&identity.id).unwrap_or(&empty_rules);

        // Check for explicit denies at this level — deny at any level blocks everything
        for key in keys {
            for rule in rules {
                if rule.effect == PermissionEffect::Deny
                    && glob_match::glob_match(&rule.action_pattern, &key.0)
                {
                    return ChainWalkResult::Denied(format!(
                        "denied by rule at {}: {}",
                        identity.name, rule.action_pattern
                    ));
                }
            }
        }

        // Check allow coverage
        let uncovered: Vec<PermissionKey> = keys
            .iter()
            .filter(|k| {
                !rules.iter().any(|r| {
                    r.effect == PermissionEffect::Allow
                        && glob_match::glob_match(&r.action_pattern, &k.0)
                })
            })
            .cloned()
            .collect();

        if uncovered.is_empty() {
            // Fully covered by explicit rules at this level
            continue;
        }

        if identity.inherit_permissions && identity.parent_id.is_some() {
            // Skip — parent's rules will be checked at the parent level
            continue;
        }

        // GAP: not covered and not inheriting
        // Ancestors = identities above this one (earlier in chain, excluding this one)
        let chain_pos = chain.len() - 1 - rev_idx;
        let ancestors: Vec<Uuid> = chain[..chain_pos].iter().map(|a| a.id).collect();

        gaps.push(PermissionGap {
            gap_identity_id: identity.id,
            gap_identity_name: identity.name.clone(),
            uncovered_keys: uncovered,
            can_be_handled_by: ancestors,
        });
    }

    if gaps.is_empty() {
        ChainWalkResult::Allowed
    } else {
        ChainWalkResult::NeedsApproval(gaps)
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

    fn identity(name: &str, parent_id: Option<Uuid>, inherit: bool) -> ChainIdentity {
        ChainIdentity {
            id: Uuid::new_v4(),
            name: name.to_string(),
            parent_id,
            inherit_permissions: inherit,
        }
    }

    // --- Flat check_permissions tests (unchanged) ---

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

    // --- Chain walk tests ---

    fn rules_for(id: Uuid, pattern: &str, effect: PermissionEffect) -> PermissionRule {
        PermissionRule {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            identity_id: id,
            action_pattern: pattern.to_string(),
            effect,
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn chain_single_level_flat_identity() {
        // Single user with rules — same as flat check
        let user = identity("alice", None, false);
        let chain = vec![user.clone()];
        let mut rules_map = HashMap::new();
        rules_map.insert(
            user.id,
            vec![rules_for(
                user.id,
                "http:GET:api.github.com/**",
                PermissionEffect::Allow,
            )],
        );
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        assert!(matches!(
            resolve_chain(&chain, &rules_map, &keys),
            ChainWalkResult::Allowed
        ));
    }

    #[test]
    fn chain_two_level_agent_inherits() {
        // User has rules, agent inherits
        let user = identity("alice", None, false);
        let agent = identity("henry", Some(user.id), true);
        let chain = vec![user.clone(), agent.clone()];
        let mut rules_map = HashMap::new();
        rules_map.insert(
            user.id,
            vec![rules_for(
                user.id,
                "http:GET:api.github.com/**",
                PermissionEffect::Allow,
            )],
        );
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        assert!(matches!(
            resolve_chain(&chain, &rules_map, &keys),
            ChainWalkResult::Allowed
        ));
    }

    #[test]
    fn chain_two_level_gap_at_agent() {
        // Agent has no rules and doesn't inherit → gap at agent
        let user = identity("alice", None, false);
        let agent = identity("henry", Some(user.id), false);
        let chain = vec![user.clone(), agent.clone()];
        let mut rules_map = HashMap::new();
        rules_map.insert(
            user.id,
            vec![rules_for(
                user.id,
                "http:GET:api.github.com/**",
                PermissionEffect::Allow,
            )],
        );
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        match resolve_chain(&chain, &rules_map, &keys) {
            ChainWalkResult::NeedsApproval(gaps) => {
                assert_eq!(gaps.len(), 1);
                assert_eq!(gaps[0].gap_identity_id, agent.id);
                assert_eq!(gaps[0].can_be_handled_by, vec![user.id]);
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn chain_three_level_gap_at_middle() {
        // User has rules, agent has no rules (gap), subagent inherits from agent
        let user = identity("alice", None, false);
        let agent = identity("henry", Some(user.id), false);
        let subagent = identity("researcher", Some(agent.id), true);
        let chain = vec![user.clone(), agent.clone(), subagent.clone()];
        let mut rules_map = HashMap::new();
        rules_map.insert(
            user.id,
            vec![rules_for(
                user.id,
                "http:GET:api.github.com/**",
                PermissionEffect::Allow,
            )],
        );
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        match resolve_chain(&chain, &rules_map, &keys) {
            ChainWalkResult::NeedsApproval(gaps) => {
                assert_eq!(gaps.len(), 1);
                assert_eq!(gaps[0].gap_identity_id, agent.id);
                assert_eq!(gaps[0].can_be_handled_by, vec![user.id]);
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn chain_deny_at_any_level_blocks() {
        // Deny at user level blocks even if agent has allow
        let user = identity("alice", None, false);
        let agent = identity("henry", Some(user.id), false);
        let chain = vec![user.clone(), agent.clone()];
        let mut rules_map = HashMap::new();
        rules_map.insert(
            user.id,
            vec![rules_for(user.id, "http:DELETE:**", PermissionEffect::Deny)],
        );
        rules_map.insert(
            agent.id,
            vec![rules_for(
                agent.id,
                "http:DELETE:**",
                PermissionEffect::Allow,
            )],
        );
        let keys = vec![PermissionKey("http:DELETE:api.github.com/repos/x".into())];
        assert!(matches!(
            resolve_chain(&chain, &rules_map, &keys),
            ChainWalkResult::Denied(_)
        ));
    }

    #[test]
    fn chain_multiple_gaps() {
        // Agent and subagent both have gaps
        let user = identity("alice", None, false);
        let agent = identity("henry", Some(user.id), false);
        let subagent = identity("researcher", Some(agent.id), false);
        let chain = vec![user.clone(), agent.clone(), subagent.clone()];
        let mut rules_map = HashMap::new();
        rules_map.insert(
            user.id,
            vec![rules_for(
                user.id,
                "http:GET:api.github.com/**",
                PermissionEffect::Allow,
            )],
        );
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        match resolve_chain(&chain, &rules_map, &keys) {
            ChainWalkResult::NeedsApproval(gaps) => {
                assert_eq!(gaps.len(), 2);
                // First gap should be subagent (walked leaf-to-root, but gaps collected in walk order)
                let gap_ids: Vec<Uuid> = gaps.iter().map(|g| g.gap_identity_id).collect();
                assert!(gap_ids.contains(&subagent.id));
                assert!(gap_ids.contains(&agent.id));
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn chain_cascading_inherit_three_levels() {
        // Subagent inherits from agent, agent inherits from user, user has rules
        let user = identity("alice", None, false);
        let agent = identity("henry", Some(user.id), true);
        let subagent = identity("researcher", Some(agent.id), true);
        let chain = vec![user.clone(), agent.clone(), subagent.clone()];
        let mut rules_map = HashMap::new();
        rules_map.insert(
            user.id,
            vec![rules_for(
                user.id,
                "http:GET:api.github.com/**",
                PermissionEffect::Allow,
            )],
        );
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        assert!(matches!(
            resolve_chain(&chain, &rules_map, &keys),
            ChainWalkResult::Allowed
        ));
    }

    #[test]
    fn chain_empty_keys_always_allowed() {
        let user = identity("alice", None, false);
        let chain = vec![user];
        assert!(matches!(
            resolve_chain(&chain, &HashMap::new(), &[]),
            ChainWalkResult::Allowed
        ));
    }
}
