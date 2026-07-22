use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::service::{Risk, ScopeParams};
use crate::types::{PermissionEffect, PermissionRule};

/// A derived permission key from an action request.
///
/// Two formats depending on call shape (SPEC §8):
/// - Service + defined action: `{service}:{action}:{arg}`
/// - Service + HTTP verb: `{service}:{METHOD}:{path}` (with the synthetic
///   `http` pseudo-service, the `path` segment is `host[:port]/path?query`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionKey(pub String);

/// A parsed permission key with its structural components exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedKey {
    pub key: String,
    pub service: String,
    pub action: String,
    /// The third segment verbatim, `label=value` included. Surfaces that match
    /// or display the raw key use this; surfaces that want the two halves read
    /// [`label`](Self::label) and [`value`](Self::value).
    pub arg: String,
    /// The scope label when the arg carries one (`recipient` in
    /// `email:send:recipient=jane@example.com`). `None` for a bare arg — every
    /// key written before labels existed, and every rule an operator types by
    /// hand.
    ///
    /// A label is not a param name: `to`, `cc`, and `bcc` all file under
    /// `recipient`, which is no param at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The arg with any `label=` prefix stripped.
    pub value: String,
}

/// A suggested tier of permission keys at a specific broadness level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedTier {
    pub keys: Vec<String>,
    pub description: String,
}

impl PermissionKey {
    /// Derive permission keys from a Service + HTTP verb request (SPEC §8).
    /// Format: `{service}:{METHOD}:{path}` — host is omitted because the
    /// service instance bounds it via `svc.hosts`.
    ///
    /// The method is normalized to uppercase so `"post"` and `"POST"` both
    /// match a rule like `github:POST:/**`. Permission rules are written
    /// with uppercase methods by convention; without normalization, a
    /// caller using lowercase would silently fail authorization.
    pub fn from_service_http(service_key: &str, method: &str, path: &str) -> Vec<Self> {
        let method = method.to_ascii_uppercase();
        vec![Self(format!("{service_key}:{method}:{path}"))]
    }

    /// Derive permission keys from a service action request.
    /// Format: `{service}:{action}:{label}={value}`, where the label and value
    /// come from `scope_param`. An unscoped action derives `{service}:{action}:*`.
    ///
    /// Two fan-outs happen here, and both exist so a grant can be about one
    /// concrete thing rather than the whole action:
    ///
    /// - An **array-valued** param yields one key per element instead of
    ///   stringifying the array. A send to two recipients derives two keys, so
    ///   `email:send:*@example.com` covers the internal one while the external
    ///   one bubbles as an approval naming only itself. Without it the arg
    ///   would be the JSON literal `["a@b.com","c@d.com"]` — unmatchable by any
    ///   rule and unreadable by any human.
    /// - **Several scoped params** each contribute their values. `to`, `cc`,
    ///   and `bcc` all mint keys, so a bcc to an outsider is gated exactly like
    ///   a to.
    ///
    /// The label is what decides whether two params share a namespace: authored
    /// as `to:recipient`/`cc:recipient` they collapse into one
    /// `recipient=<addr>` key (one approval for an address on both headers);
    /// authored bare they stay distinguishable as `to=`/`cc=`.
    ///
    /// Keys are deduped (order-preserving) so a repeated value does not raise
    /// the same approval twice. No values at all — every scoped param missing,
    /// or all of them empty arrays — falls back to `*`.
    pub fn from_service_action(
        service_key: &str,
        action_key: &str,
        scope_param: &ScopeParams,
        params: &HashMap<String, serde_json::Value>,
    ) -> Vec<Self> {
        let mut seen = std::collections::HashSet::new();
        let keys: Vec<Self> = scope_param
            .refs()
            .iter()
            .flat_map(|r| {
                let values: Vec<String> = match params.get(&r.param) {
                    Some(serde_json::Value::Array(items)) => {
                        items.iter().map(Self::scope_arg).collect()
                    }
                    Some(v) => vec![Self::scope_arg(v)],
                    None => Vec::new(),
                };
                let label = r.label.clone();
                values
                    .into_iter()
                    .map(move |v| format!("{service_key}:{action_key}:{label}={v}"))
            })
            .filter(|k| seen.insert(k.clone()))
            .map(Self)
            .collect();
        if keys.is_empty() {
            return vec![Self(format!("{service_key}:{action_key}:*"))];
        }
        keys
    }

    /// Render one `scope_param` value as the `{arg}` segment. Strings pass
    /// through unquoted; anything else falls back to its JSON form.
    fn scope_arg(v: &serde_json::Value) -> String {
        match v.as_str() {
            Some(s) => s.to_string(),
            None => v.to_string(),
        }
    }
}

/// Parse a flat permission key string into its structured components.
/// Format: `{service}:{action}:{arg}` where arg may contain colons, and may
/// itself be `{label}={value}`.
pub fn parse_derived_key(key: &str) -> DerivedKey {
    let mut parts = key.splitn(3, ':');
    let service = parts.next().unwrap_or("").to_string();
    let action = parts.next().unwrap_or("").to_string();
    let arg = parts.next().unwrap_or("*").to_string();
    let (label, value) = split_scope_arg(&arg);
    DerivedKey {
        key: key.to_string(),
        service,
        action,
        arg,
        label,
        value,
    }
}

/// Split a `{label}={value}` arg. The prefix only counts as a label when it is
/// a bare identifier, so a value that itself contains `=` (a query string, a
/// base64 pad) is returned whole rather than sliced at an arbitrary `=`.
fn split_scope_arg(arg: &str) -> (Option<String>, String) {
    match arg.split_once('=') {
        Some((label, value)) if crate::types::is_scope_ident(label) => {
            (Some(label.to_string()), value.to_string())
        }
        _ => (None, arg.to_string()),
    }
}

/// The strings a rule may be matched against for one key.
///
/// A labelled key also answers to its **value-only** form, so a rule written
/// before labels existed — or written deliberately label-agnostic, like
/// `email:send:*@example.com` — still covers it no matter which param carried
/// the value. A `label=`-qualified rule only matches keys with that label,
/// which is what makes `email:send:cc=*@example.com` narrower than the bare
/// form rather than a synonym for it.
fn match_forms(key: &str) -> Vec<String> {
    let dk = parse_derived_key(key);
    match dk.label {
        Some(_) => vec![
            key.to_string(),
            format!("{}:{}:{}", dk.service, dk.action, dk.value),
        ],
        None => vec![key.to_string()],
    }
}

/// Does `pattern` cover `key`, in either of the key's [`match_forms`]?
fn rule_matches(pattern: &str, key: &str) -> bool {
    match_forms(key)
        .iter()
        .any(|form| glob_match::glob_match(pattern, form))
}

/// Does the permission key `pattern` cover the concrete key `key`?
///
/// Same glob + [`match_forms`] semantics the rule engine uses, exposed for
/// callers that need to validate a hand-typed key against what a request
/// actually asked for (e.g. an approval's "Custom…" remember key) without
/// synthesizing a `PermissionRule`.
pub fn key_covers(pattern: &str, key: &str) -> bool {
    rule_matches(pattern, key)
}

/// Parse all permission key strings into structured `DerivedKey`s.
pub fn derive_keys(permission_keys: &[String]) -> Vec<DerivedKey> {
    permission_keys
        .iter()
        .map(|k| parse_derived_key(k))
        .collect()
}

/// Compute the broadening ladder for a single derived key.
/// Returns a list of progressively broader key strings (including the original).
fn broadening_ladder(dk: &DerivedKey) -> Vec<String> {
    let mut ladder = vec![dk.key.clone()];

    match dk.service.as_str() {
        "http" => {
            // http:{METHOD}:{host}{path} → http:{METHOD}:{host}/** → http:ANY:{host}/**
            let host = dk.arg.split('/').next().unwrap_or(&dk.arg);
            let host_wildcard = format!("http:{}:{host}/**", dk.action);
            if host_wildcard != dk.key {
                ladder.push(host_wildcard);
            }
            if dk.action != "ANY" {
                ladder.push(format!("http:ANY:{host}/**"));
            }
        }
        "secret" => {
            // secret:{name}:{target} → secret:{name}:*
            if dk.arg != "*" {
                ladder.push(format!("secret:{}:*", dk.action));
            }
        }
        _ => {
            // Service-HTTP keys (`{service}:{METHOD}:{path}`) carry a path
            // in `arg` starting with `/`. Path globs need `/**` because
            // `*` does not span `/` in `glob_match`. Detect and emit the
            // path-aware ladder.
            if dk.arg.starts_with('/') {
                // {service}:{METHOD}:{path} → {service}:{METHOD}:/** → {service}:*:/**
                let method_wildcard = format!("{}:{}:/**", dk.service, dk.action);
                if method_wildcard != dk.key {
                    ladder.push(method_wildcard);
                }
                ladder.push(format!("{}:*:/**", dk.service));
            } else {
                // Service action:
                // {service}:{action}:{label}={value} → {service}:{action}:{value}
                //   → {service}:{action}:* → {service}:*:*
                //
                // The value-only rung is a real widening step, not cosmetics:
                // it grants the same correspondent/resource under *any* label,
                // which for `email:send` is "this address, whichever header it
                // is on". Unlabelled args skip it.
                if dk.label.is_some() {
                    ladder.push(format!("{}:{}:{}", dk.service, dk.action, dk.value));
                }
                if dk.arg != "*" {
                    ladder.push(format!("{}:{}:*", dk.service, dk.action));
                }
                ladder.push(format!("{}:*:*", dk.service));
            }
        }
    }

    ladder
}

/// Convert a snake_case action name to human-readable form.
/// e.g., "create_pull_request" → "Create pull request"
fn humanize_action(action: &str) -> String {
    let mut s = action.replace('_', " ");
    if let Some(first) = s.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    s
}

/// Generate a human-readable description for a single derived key at a given broadness.
fn describe_key(dk: &DerivedKey) -> String {
    match dk.service.as_str() {
        "http" => {
            if dk.action == "ANY" {
                let host = dk.arg.split('/').next().unwrap_or(&dk.arg);
                if host == "*" {
                    "Any HTTP request".to_string()
                } else {
                    format!("Any request to {host}")
                }
            } else {
                format!("{} to {}", dk.action, dk.arg)
            }
        }
        "secret" => {
            if dk.arg == "*" {
                format!("{} (any target)", humanize_action(&dk.action))
            } else {
                humanize_action(&dk.action)
            }
        }
        _ => {
            if dk.action == "*" {
                format!("Any {} action", humanize_action(&dk.service))
            } else if dk.arg == "*" {
                format!("{} on any resource", humanize_action(&dk.action))
            } else if let Some(ref label) = dk.label {
                // "Send on recipient=jane@example.com" reads like a bug; the
                // label is a noun the approver already understands.
                format!("{} on {} {}", humanize_action(&dk.action), label, dk.value)
            } else {
                format!("{} on {}", humanize_action(&dk.action), dk.arg)
            }
        }
    }
}

/// Drop repeats while keeping first-seen order.
fn dedup_preserving(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

/// Generate a combined description for a tier's set of derived keys.
fn generate_tier_description(keys: &[DerivedKey]) -> String {
    // Separate primary keys (http/service-action) from auxiliary (secret)
    let primary: Vec<&DerivedKey> = keys.iter().filter(|k| k.service != "secret").collect();
    let secrets: Vec<&DerivedKey> = keys.iter().filter(|k| k.service == "secret").collect();

    // At the broader rungs several keys collapse onto the same phrase — two
    // recipients both become "Send on any resource". Say it once.
    let mut desc = if primary.is_empty() {
        keys.first().map(describe_key).unwrap_or_default()
    } else {
        dedup_preserving(primary.iter().map(|k| describe_key(k))).join(", ")
    };

    if !secrets.is_empty() {
        let secret_names = dedup_preserving(secrets.iter().map(|s| s.action.clone()));
        desc.push_str(&format!(" with {}", secret_names.join(", ")));
    }

    desc
}

/// Generate 2-4 suggested tiers of progressively broader permission keys.
pub fn suggest_tiers(permission_keys: &[String]) -> Vec<SuggestedTier> {
    if permission_keys.is_empty() {
        return vec![];
    }

    let derived = derive_keys(permission_keys);
    let ladders: Vec<Vec<String>> = derived.iter().map(broadening_ladder).collect();

    // Determine the max ladder length
    let max_len = ladders.iter().map(|l| l.len()).max().unwrap_or(1);

    let mut tiers: Vec<SuggestedTier> = Vec::new();
    let mut prev_keys: Option<Vec<String>> = None;

    for i in 0..max_len {
        // For each key, pick the tier at index i (or the last available)
        // Several keys converge on the same rung as the ladders broaden — an
        // N-recipient send collapses to one `svc:send:*`. Dedupe so the tier
        // (and the rules "Allow & Remember" writes from it) carries each key
        // once.
        let tier_keys: Vec<String> = dedup_preserving(ladders.iter().map(|ladder| {
            let idx = i.min(ladder.len() - 1);
            ladder[idx].clone()
        }));

        // Deduplicate: skip if same as previous tier
        if prev_keys.as_ref() == Some(&tier_keys) {
            continue;
        }

        // Build derived keys for this tier's key set to generate description
        let tier_derived: Vec<DerivedKey> =
            tier_keys.iter().map(|k| parse_derived_key(k)).collect();
        let description = generate_tier_description(&tier_derived);

        prev_keys = Some(tier_keys.clone());
        tiers.push(SuggestedTier {
            keys: tier_keys,
            description,
        });
    }

    // Cap at 4 tiers: keep first, last, and evenly spaced middle ones
    if tiers.len() > 4 {
        let last = tiers.len() - 1;
        let mid1 = last / 3;
        let mid2 = 2 * last / 3;
        tiers = vec![
            tiers[0].clone(),
            tiers[mid1].clone(),
            tiers[mid2].clone(),
            tiers[last].clone(),
        ];
    }

    tiers
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
            if rule.effect == PermissionEffect::Deny && rule_matches(&rule.action_pattern, &key.0) {
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
            rule.effect == PermissionEffect::Allow && rule_matches(&rule.action_pattern, &key.0)
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

// ── Layer 1: Group Ceiling ───────────────────────────────────────────

/// Access level hierarchy for group grants.
/// Maps to the existing `Risk` enum: read < write < admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessLevel {
    Read,
    Write,
    Admin,
}

impl AccessLevel {
    /// Does this access level permit the given risk?
    pub fn permits_risk(self, risk: Risk) -> bool {
        match self {
            AccessLevel::Admin => true,
            AccessLevel::Write => matches!(risk, Risk::Read | Risk::Write),
            AccessLevel::Read => matches!(risk, Risk::Read),
        }
    }

    /// Parse from a string. Returns `None` for invalid values.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(AccessLevel::Read),
            "write" => Some(AccessLevel::Write),
            "admin" => Some(AccessLevel::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessLevel::Read => write!(f, "read"),
            AccessLevel::Write => write!(f, "write"),
            AccessLevel::Admin => write!(f, "admin"),
        }
    }
}

/// A resolved group grant for ceiling checking.
#[derive(Debug, Clone)]
pub struct CeilingGrant {
    pub service_name: String,
    pub access_level: AccessLevel,
    pub auto_approve_reads: bool,
}

/// Result of a group ceiling check.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupCeilingResult {
    /// Within the ceiling. `read_bypass` is true when the matching grant has
    /// `auto_approve_reads = true` and the action is non-mutating — callers
    /// should skip Layer 2 (no permission rule written, no approval filed).
    WithinCeiling { read_bypass: bool },
    /// Exceeds ceiling — denied, not approvable.
    ExceedsCeiling(String),
    /// Identity has no groups assigned — no ceiling enforced (permissive).
    NoGroups,
}

/// Check if a request is within the group ceiling.
///
/// - `service_name`: the resolved service name (e.g., "github", or "http"
///   for raw HTTP via the system-managed singleton instance)
/// - `risk`: the action's risk level
/// - `grants`: all grants from the owner-user's groups
/// - `has_groups`: whether the user has any group assignments
///
/// `http` is no longer a special case: the org's system-managed `http`
/// service instance is treated as any other service. Access level on the
/// grant gates the verb (read = GET/HEAD/OPTIONS, write = + POST/PUT/PATCH,
/// admin = + DELETE) via the standard `permits_risk` mapping.
pub fn check_group_ceiling(
    service_name: &str,
    risk: Risk,
    grants: &[CeilingGrant],
    has_groups: bool,
) -> GroupCeilingResult {
    if !has_groups {
        return GroupCeilingResult::NoGroups;
    }

    // Find matching grant(s) for this service across all groups
    let matching: Vec<&CeilingGrant> = grants
        .iter()
        .filter(|g| g.service_name == service_name)
        .collect();

    if matching.is_empty() {
        return GroupCeilingResult::ExceedsCeiling(format!(
            "service '{}' not granted by any group",
            service_name
        ));
    }

    // Check if any matching grant permits this risk level (take the most permissive)
    let permitted = matching.iter().any(|g| g.access_level.permits_risk(risk));
    if !permitted {
        return GroupCeilingResult::ExceedsCeiling(format!(
            "access level insufficient for {} on '{}'",
            risk, service_name
        ));
    }

    // Read bypass: non-mutating risk AND at least one matching grant flips the flag.
    let read_bypass = !risk.is_mutating() && matching.iter().any(|g| g.auto_approve_reads);

    GroupCeilingResult::WithinCeiling { read_bypass }
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
    fn derive_keys_from_service_http() {
        let keys = PermissionKey::from_service_http("github", "POST", "/repos/x/pulls");
        assert_eq!(keys[0].0, "github:POST:/repos/x/pulls");
    }

    #[test]
    fn derive_keys_for_http_pseudo_service_via_service_http() {
        // The synthetic `http` pseudo-service uses the same `from_service_http`
        // builder. The path segment carries `host[:port]/path?query` (no
        // leading `/`) so the produced key matches the legacy raw-HTTP shape.
        let keys = PermissionKey::from_service_http("http", "POST", "api.github.com/repos/x/pulls");
        assert_eq!(keys[0].0, "http:POST:api.github.com/repos/x/pulls");
    }

    #[test]
    fn derive_keys_from_service_http_uppercases_method() {
        let keys = PermissionKey::from_service_http("github", "post", "/repos/x/pulls");
        assert_eq!(keys[0].0, "github:POST:/repos/x/pulls");
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
            &"repo".into(),
            &params,
        );
        assert_eq!(
            keys[0].0,
            "github:create_pull_request:repo=overfolder/backend"
        );
    }

    #[test]
    fn service_action_array_scope_param_fans_out_per_element() {
        let mut params = HashMap::new();
        params.insert(
            "to".to_string(),
            serde_json::json!(["a@example.com", "b@example.org"]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:to=a@example.com", "email:send:to=b@example.org"]
        );
    }

    /// A grant scoped to one domain covers only the recipients in it; the rest
    /// stay uncovered and bubble as an approval naming just them.
    #[test]
    fn domain_scoped_rule_covers_only_matching_recipients() {
        let mut params = HashMap::new();
        params.insert(
            "to".to_string(),
            serde_json::json!(["a@example.com", "b@example.org"]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        let covered: Vec<&str> = keys
            .iter()
            .filter(|k| rule_matches("email:send:*@example.com", &k.0))
            .map(|k| k.0.as_str())
            .collect();
        assert_eq!(covered, vec!["email:send:to=a@example.com"]);
    }

    #[test]
    fn service_action_array_scope_param_dedups_repeated_elements() {
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!(["a@b.com", "a@b.com"]));
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "email:send:to=a@b.com");
    }

    #[test]
    fn service_action_empty_array_scope_param_falls_back_to_wildcard() {
        // No recipient carries no scope, so the key is as broad as a missing
        // param — and a domain-scoped rule therefore does not cover it.
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!([]));
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "email:send:*");
        assert!(!rule_matches("email:send:*@example.com", &keys[0].0));
    }

    #[test]
    fn service_action_scope_param_missing_value() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action(
            "github",
            "create_pull_request",
            &"repo".into(),
            &params,
        );
        assert_eq!(keys[0].0, "github:create_pull_request:*");
    }

    #[test]
    fn service_action_no_scope_param() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action(
            "github",
            "list_repos",
            &ScopeParams::default(),
            &params,
        );
        assert_eq!(keys[0].0, "github:list_repos:*");
    }

    /// Recipient params: a shared label puts every header in one namespace,
    /// so the same address on `to` and `cc` is one key — one approval to
    /// resolve, not two for what a human reads as a single decision.
    fn recipient_scope() -> ScopeParams {
        ScopeParams::parse_list(["to:recipient", "cc:recipient", "bcc:recipient"]).unwrap()
    }

    fn recipients(
        to: serde_json::Value,
        cc: serde_json::Value,
        bcc: serde_json::Value,
    ) -> HashMap<String, serde_json::Value> {
        HashMap::from([
            ("to".to_string(), to),
            ("cc".to_string(), cc),
            ("bcc".to_string(), bcc),
        ])
    }

    #[test]
    fn shared_label_unions_every_scoped_param() {
        let params = recipients(
            serde_json::json!(["a@example.com"]),
            serde_json::json!(["b@example.com"]),
            serde_json::json!(["c@example.net"]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "email:send:recipient=a@example.com",
                "email:send:recipient=b@example.com",
                "email:send:recipient=c@example.net"
            ]
        );
    }

    #[test]
    fn shared_label_collapses_an_address_on_two_headers() {
        let params = recipients(
            serde_json::json!(["a@example.com"]),
            serde_json::json!(["a@example.com"]),
            serde_json::json!([]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:recipient=a@example.com"]
        );
    }

    /// Without a shared label the params keep their own namespaces — which is
    /// the point of making the label author-controlled rather than implicit.
    #[test]
    fn unlabelled_params_keep_distinct_namespaces() {
        let params = recipients(
            serde_json::json!(["a@example.com"]),
            serde_json::json!(["a@example.com"]),
            serde_json::json!([]),
        );
        let scope = ScopeParams::parse_list(["to", "cc", "bcc"]).unwrap();
        let keys = PermissionKey::from_service_action("email", "send", &scope, &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:to=a@example.com", "email:send:cc=a@example.com"]
        );
    }

    #[test]
    fn scoped_params_absent_from_the_call_contribute_nothing() {
        // Only `to` was supplied; cc/bcc are simply not in the args.
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!(["a@example.com"]));
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:recipient=a@example.com"]
        );
    }

    #[test]
    fn every_scoped_param_empty_falls_back_to_wildcard() {
        let params = recipients(
            serde_json::json!([]),
            serde_json::json!([]),
            serde_json::json!([]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:*"]
        );
    }

    #[test]
    fn scalar_and_array_scoped_params_mix() {
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!("a@example.com"));
        params.insert("cc".to_string(), serde_json::json!(["b@example.com"]));
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "email:send:recipient=a@example.com",
                "email:send:recipient=b@example.com"
            ]
        );
    }

    // ── Value-only rules stay label-agnostic ─────────────────────────────

    /// The compat direction that matters, and the only one that can be
    /// inferred: rules are long-lived, keys are re-derived on every call, so a
    /// grant written before labels existed must keep covering the labelled key
    /// the same call derives today. The value-only match form bridges them.
    #[test]
    fn value_only_rule_covers_a_labelled_key() {
        let rules = vec![rule("email:send:*@example.com", PermissionEffect::Allow)];
        let keys = vec![PermissionKey("email:send:recipient=a@example.com".into())];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    #[test]
    fn label_qualified_rule_does_not_cover_another_label() {
        let rules = vec![rule("email:send:cc=*@example.com", PermissionEffect::Allow)];
        let cc = vec![PermissionKey("email:send:cc=a@example.com".into())];
        assert_eq!(check_permissions(&rules, &cc), PermissionResult::Allowed);

        let to = vec![PermissionKey("email:send:to=a@example.com".into())];
        assert_eq!(
            check_permissions(&rules, &to),
            PermissionResult::NeedsApproval(to.clone()),
            "a cc-scoped grant must not launder the same address on `to`"
        );
    }

    /// The reverse direction does **not** hold, deliberately: a `label=`-
    /// qualified rule does not cover a *label-less* key.
    ///
    /// This is reachable, because approvals persist their derived keys and
    /// `cascade_resolve` re-matches those stored strings against rules written
    /// later. An approval filed before labels shipped holds
    /// `email:send:a@example.com`; a rule remembered afterwards may well be
    /// `email:send:recipient=a@example.com`, and the two do not match.
    ///
    /// Matching them would mean guessing: the stored key records no label, so
    /// nothing says whether that address was a `to`, a `cc`, or a `bcc`, and
    /// honouring a `cc=`-scoped grant over it would grant strictly more than
    /// the operator wrote. Failing closed costs one human click on approvals
    /// filed in the window before the upgrade (they expire in
    /// `APPROVAL_EXPIRY_SECS`, 30 min by default); failing open would silently
    /// widen a narrow grant. Operators who want the old keys covered write the
    /// value-only form, which is the tier the ladder offers directly beneath
    /// the labelled one.
    #[test]
    fn a_labelled_rule_does_not_cover_a_label_less_key() {
        let legacy = vec![PermissionKey("email:send:a@example.com".into())];

        for pattern in [
            "email:send:recipient=a@example.com",
            "email:send:recipient=*@example.com",
        ] {
            let rules = vec![rule(pattern, PermissionEffect::Allow)];
            assert_eq!(
                check_permissions(&rules, &legacy),
                PermissionResult::NeedsApproval(legacy.clone()),
                "{pattern} must not cover a key that records no label"
            );
        }

        // The value-only form is the one that does cover it.
        let rules = vec![rule("email:send:*@example.com", PermissionEffect::Allow)];
        assert_eq!(
            check_permissions(&rules, &legacy),
            PermissionResult::Allowed
        );
    }

    #[test]
    fn value_only_deny_denies_whatever_label_carries_it() {
        let rules = vec![
            rule("email:send:*", PermissionEffect::Allow),
            rule("email:send:blocked@example.com", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "email:send:recipient=blocked@example.com".into(),
        )];
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::Denied(_)
        ));
    }

    /// `=` inside a *value* must not be mistaken for a label separator — the
    /// prefix only counts when it is a bare identifier.
    #[test]
    fn a_non_identifier_prefix_is_not_a_label() {
        let dk = parse_derived_key("http:GET:api.example.com/x?a=1");
        assert_eq!(dk.label, None);
        assert_eq!(dk.value, "api.example.com/x?a=1");
        assert_eq!(match_forms(&dk.key), vec!["http:GET:api.example.com/x?a=1"]);
    }

    /// The split is lexical, so an arg that merely *reads* like `ident=rest` is
    /// taken as labelled and therefore also answers to its value-only form.
    /// Pinned because it widens what a rule matches: the exact key matches as
    /// always, and `sheets:query:* from t` now matches too. Derived args are
    /// `*`, a URL/host, or a real `label=` scope value, so this only concerns
    /// hand-written rules.
    #[test]
    fn an_identifier_prefix_is_always_read_as_a_label() {
        let dk = parse_derived_key("sheets:query:select=* from t");
        assert_eq!(dk.label.as_deref(), Some("select"));
        assert_eq!(dk.value, "* from t");

        let keys = vec![PermissionKey("sheets:query:select=* from t".into())];
        let exact = vec![rule("sheets:query:select=*", PermissionEffect::Allow)];
        assert_eq!(check_permissions(&exact, &keys), PermissionResult::Allowed);
        let value_only = vec![rule("sheets:query:* from t", PermissionEffect::Allow)];
        assert_eq!(
            check_permissions(&value_only, &keys),
            PermissionResult::Allowed
        );
    }

    #[test]
    fn parse_derived_key_splits_the_label() {
        let dk = parse_derived_key("email:send:recipient=jane@example.com");
        assert_eq!(dk.service, "email");
        assert_eq!(dk.action, "send");
        assert_eq!(dk.arg, "recipient=jane@example.com");
        assert_eq!(dk.label.as_deref(), Some("recipient"));
        assert_eq!(dk.value, "jane@example.com");
    }

    #[test]
    fn describe_key_reads_the_label_as_a_noun() {
        let dk = parse_derived_key("email:send:recipient=jane@example.com");
        assert_eq!(describe_key(&dk), "Send on recipient jane@example.com");
    }

    /// The ladder gains one rung for a labelled key: the same value under any
    /// label ("this correspondent, whichever header").
    #[test]
    fn broadening_ladder_offers_the_value_only_rung() {
        let dk = parse_derived_key("email:send:recipient=jane@example.com");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "email:send:recipient=jane@example.com",
                "email:send:jane@example.com",
                "email:send:*",
                "email:*:*"
            ]
        );
    }

    #[test]
    fn broadening_ladder_unchanged_for_unlabelled_args() {
        let dk = parse_derived_key("github:create_pull_request:overfolder/backend");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "github:create_pull_request:overfolder/backend",
                "github:create_pull_request:*",
                "github:*:*"
            ]
        );
    }

    #[test]
    fn glob_matches_service_action_keys() {
        let rules = vec![rule("github:*:overfolder/*", PermissionEffect::Allow)];
        let keys = vec![PermissionKey(
            "github:create_pull_request:overfolder/backend".into(),
        )];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    /// Service-HTTP keys (`{service}:{METHOD}:{path}`) need globstar (`/**`)
    /// to span path segments — plain `*` does not match across `/`. Pin the
    /// matching contract so a rule like `github:POST:/**` actually allows
    /// `github:POST:/repos/x/pulls`.
    #[test]
    fn glob_matches_service_http_keys_with_globstar() {
        let rules = vec![rule("github:POST:/**", PermissionEffect::Allow)];
        let keys = PermissionKey::from_service_http("github", "POST", "/repos/x/pulls");
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    /// Sanity: `*` (without globstar) does NOT match a path containing `/`.
    /// This is what motivates the path-aware broadening ladder for
    /// service-HTTP keys (it suggests `/**`, not `*`).
    #[test]
    fn glob_star_without_globstar_does_not_span_slashes() {
        let rules = vec![rule("github:POST:*", PermissionEffect::Allow)];
        let keys = PermissionKey::from_service_http("github", "POST", "/repos/x/pulls");
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::NeedsApproval { .. }
        ));
    }

    #[test]
    fn broadening_ladder_for_service_http_uses_globstar() {
        let dk = parse_derived_key("github:POST:/repos/x/pulls");
        let ladder = broadening_ladder(&dk);
        assert_eq!(
            ladder,
            vec![
                "github:POST:/repos/x/pulls".to_string(),
                "github:POST:/**".to_string(),
                "github:*:/**".to_string(),
            ]
        );
    }

    /// SPEC §5: the `http` pseudo-service ladder must NEVER suggest
    /// `http:*:*` or `http:VERB:*` — only host-scoped wildcards
    /// (`http:VERB:host/**` and `http:ANY:host/**`).
    #[test]
    fn broadening_ladder_for_http_never_emits_unscoped_wildcards() {
        let dk = parse_derived_key("http:POST:api.github.com/v3/repos");
        let ladder = broadening_ladder(&dk);
        assert_eq!(
            ladder,
            vec![
                "http:POST:api.github.com/v3/repos".to_string(),
                "http:POST:api.github.com/**".to_string(),
                "http:ANY:api.github.com/**".to_string(),
            ]
        );
        for rung in &ladder {
            assert!(
                !rung.starts_with("http:*:") && !rung.ends_with(":*"),
                "ladder must not suggest unbounded http wildcards (got {rung:?})"
            );
        }
    }

    // ── DerivedKey / SuggestedTier tests ───────────────────────────────

    #[test]
    fn parse_service_action_key() {
        let dk = parse_derived_key("github:create_pull_request:overfolder/backend");
        assert_eq!(dk.service, "github");
        assert_eq!(dk.action, "create_pull_request");
        assert_eq!(dk.arg, "overfolder/backend");
    }

    #[test]
    fn parse_http_key() {
        let dk = parse_derived_key("http:POST:api.github.com/repos/x/pulls");
        assert_eq!(dk.service, "http");
        assert_eq!(dk.action, "POST");
        assert_eq!(dk.arg, "api.github.com/repos/x/pulls");
    }

    #[test]
    fn parse_key_with_star_arg() {
        let dk = parse_derived_key("github:list_repos:*");
        assert_eq!(dk.arg, "*");
    }

    #[test]
    fn parse_key_missing_arg_defaults_to_star() {
        let dk = parse_derived_key("github:list_repos");
        assert_eq!(dk.arg, "*");
    }

    #[test]
    fn tiers_single_service_action() {
        let keys = vec!["github:create_pull_request:overfolder/backend".to_string()];
        let tiers = suggest_tiers(&keys);
        assert_eq!(tiers.len(), 3);
        assert_eq!(
            tiers[0].keys,
            vec!["github:create_pull_request:overfolder/backend"]
        );
        assert_eq!(tiers[1].keys, vec!["github:create_pull_request:*"]);
        assert_eq!(tiers[2].keys, vec!["github:*:*"]);
    }

    #[test]
    fn tiers_single_http_key() {
        let keys = vec!["http:POST:api.stripe.com/v1/charges".to_string()];
        let tiers = suggest_tiers(&keys);
        assert_eq!(tiers.len(), 3);
        assert_eq!(tiers[0].keys, vec!["http:POST:api.stripe.com/v1/charges"]);
        assert_eq!(tiers[1].keys, vec!["http:POST:api.stripe.com/**"]);
        assert_eq!(tiers[2].keys, vec!["http:ANY:api.stripe.com/**"]);
    }

    #[test]
    fn tiers_multi_key_http_plus_secret() {
        let keys = vec![
            "http:POST:api.example.com".to_string(),
            "secret:api_key:api.example.com".to_string(),
        ];
        let tiers = suggest_tiers(&keys);
        assert!(tiers.len() >= 2);
        // First tier: both exact
        assert_eq!(
            tiers[0].keys,
            vec![
                "http:POST:api.example.com",
                "secret:api_key:api.example.com"
            ]
        );
        // Last tier should be the broadest
        let last = tiers.last().unwrap();
        assert!(last.keys.iter().any(|k| k.contains("ANY")));
    }

    #[test]
    fn tiers_dedup_when_arg_is_star() {
        let keys = vec!["github:list_repos:*".to_string()];
        let tiers = suggest_tiers(&keys);
        // Tier 0 = github:list_repos:* , Tier 1 would also be github:list_repos:* (deduped), Tier 2 = github:*:*
        assert_eq!(tiers.len(), 2);
        assert_eq!(tiers[0].keys, vec!["github:list_repos:*"]);
        assert_eq!(tiers[1].keys, vec!["github:*:*"]);
    }

    /// A multi-recipient send derives one key per recipient. The exact tier
    /// must keep both, but every broader rung collapses them onto one key —
    /// and must say so once, not "Send on any resource, Send on any resource".
    #[test]
    fn tiers_multi_recipient_dedupes_broad_rungs() {
        let keys = vec![
            "email:send:recipient=ada@example.com".to_string(),
            "email:send:recipient=bob@example.com".to_string(),
        ];
        let tiers = suggest_tiers(&keys);

        assert_eq!(tiers[0].keys, keys);
        assert!(tiers[0].description.contains("ada@example.com"));
        assert!(tiers[0].description.contains("bob@example.com"));

        let broad = tiers
            .iter()
            .find(|t| t.keys == vec!["email:send:*"])
            .expect("a `send on any resource` tier");
        assert_eq!(broad.description, "Send on any resource");

        let broadest = tiers.last().unwrap();
        assert_eq!(broadest.keys, vec!["email:*:*"]);
        assert_eq!(broadest.description, "Any Email action");
    }

    #[test]
    fn key_covers_label_stripped_form() {
        assert!(key_covers(
            "email:send:*",
            "email:send:recipient=ada@example.com"
        ));
        assert!(key_covers(
            "email:send:recipient=ada@example.com",
            "email:send:recipient=ada@example.com"
        ));
        assert!(!key_covers(
            "email:send:recipient=bob@example.com",
            "email:send:recipient=ada@example.com"
        ));
        assert!(!key_covers("github:*:*", "email:send:recipient=ada@x.com"));
    }

    #[test]
    fn tiers_empty_input() {
        assert!(suggest_tiers(&[]).is_empty());
    }

    #[test]
    fn description_service_action_exact() {
        let dk = parse_derived_key("github:create_pull_request:overfolder/backend");
        assert_eq!(
            describe_key(&dk),
            "Create pull request on overfolder/backend"
        );
    }

    #[test]
    fn description_service_action_wildcard() {
        let dk = parse_derived_key("github:create_pull_request:*");
        assert_eq!(describe_key(&dk), "Create pull request on any resource");
    }

    #[test]
    fn description_service_any_action() {
        let dk = parse_derived_key("github:*:*");
        assert_eq!(describe_key(&dk), "Any Github action");
    }

    #[test]
    fn description_service_any_action_underscore() {
        let dk = parse_derived_key("google_calendar:*:*");
        assert_eq!(describe_key(&dk), "Any Google calendar action");
    }

    #[test]
    fn description_http_exact() {
        let dk = parse_derived_key("http:POST:api.stripe.com/v1/charges");
        assert_eq!(describe_key(&dk), "POST to api.stripe.com/v1/charges");
    }

    #[test]
    fn description_http_any() {
        let dk = parse_derived_key("http:ANY:api.stripe.com/**");
        assert_eq!(describe_key(&dk), "Any request to api.stripe.com");
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

    // ── Group Ceiling tests ──────────────────────────────────────────

    fn grant(service: &str, level: AccessLevel, auto_read: bool) -> CeilingGrant {
        CeilingGrant {
            service_name: service.to_string(),
            access_level: level,
            auto_approve_reads: auto_read,
        }
    }

    #[test]
    fn ceiling_no_groups_is_permissive() {
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &[], false),
            GroupCeilingResult::NoGroups,
        );
    }

    #[test]
    fn ceiling_read_allowed_by_read_grant() {
        let grants = vec![grant("github", AccessLevel::Read, false)];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
    }

    #[test]
    fn ceiling_write_denied_by_read_grant() {
        let grants = vec![grant("github", AccessLevel::Read, false)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_write_allowed_by_write_grant() {
        let grants = vec![grant("github", AccessLevel::Write, false)];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
    }

    #[test]
    fn ceiling_delete_denied_by_write_grant() {
        let grants = vec![grant("github", AccessLevel::Write, false)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_delete_allowed_by_admin_grant() {
        let grants = vec![grant("github", AccessLevel::Admin, false)];
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
    }

    #[test]
    fn ceiling_service_not_granted() {
        let grants = vec![grant("slack", AccessLevel::Write, false)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Read, &grants, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_http_allowed_by_admin_grant() {
        // After Mode A collapse, raw HTTP is gated by a normal grant on the
        // org's `http` instance — there's no special boolean. Admin permits
        // every verb (read/write/delete).
        let grants = vec![grant("http", AccessLevel::Admin, false)];
        assert_eq!(
            check_group_ceiling("http", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
        assert_eq!(
            check_group_ceiling("http", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
    }

    #[test]
    fn ceiling_http_write_denied_by_read_grant() {
        // A read-level http grant permits only GET/HEAD/OPTIONS (Risk::Read).
        let grants = vec![grant("http", AccessLevel::Read, false)];
        assert_eq!(
            check_group_ceiling("http", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
        assert!(matches!(
            check_group_ceiling("http", Risk::Write, &grants, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_http_denied_when_not_granted() {
        assert!(matches!(
            check_group_ceiling("http", Risk::Write, &[], true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_auto_approve_reads() {
        let grants = vec![grant("github", AccessLevel::Write, true)];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: true },
        );
    }

    #[test]
    fn ceiling_auto_approve_reads_not_for_writes() {
        let grants = vec![grant("github", AccessLevel::Write, true)];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
    }

    #[test]
    fn ceiling_most_permissive_grant_wins() {
        // Two groups: one with read, one with admin
        let grants = vec![
            grant("github", AccessLevel::Read, false),
            grant("github", AccessLevel::Admin, false),
        ];
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: false },
        );
    }

    #[test]
    fn ceiling_auto_approve_from_any_grant() {
        // One grant without auto_approve, one with
        let grants = vec![
            grant("github", AccessLevel::Write, false),
            grant("github", AccessLevel::Read, true),
        ];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling { read_bypass: true },
        );
    }

    #[test]
    fn access_level_parse() {
        assert_eq!(AccessLevel::parse("read"), Some(AccessLevel::Read));
        assert_eq!(AccessLevel::parse("write"), Some(AccessLevel::Write));
        assert_eq!(AccessLevel::parse("admin"), Some(AccessLevel::Admin));
        assert_eq!(AccessLevel::parse("invalid"), None);
    }
}
