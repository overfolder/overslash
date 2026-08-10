use std::fmt;

use crate::types::service::Risk;

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

    /// Does this level sit at or above `other`? Used to bound a grant's
    /// auto-approve level by its access level — the two ladders are the same,
    /// so this is just the derived `Ord`.
    pub fn permits_level(self, other: AccessLevel) -> bool {
        other <= self
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

    /// Parse an *auto-approve* level, where `"none"` is a legal value meaning
    /// "never auto-approve". The outer `Option` is the parse result; the inner
    /// one is the level itself.
    pub fn parse_auto(s: &str) -> Option<Option<Self>> {
        match s {
            "none" => Some(None),
            other => Self::parse(other).map(Some),
        }
    }

    /// Render an auto-approve level, mapping `None` back to `"none"`.
    pub fn render_auto(level: Option<Self>) -> &'static str {
        match level {
            None => "none",
            Some(AccessLevel::Read) => "read",
            Some(AccessLevel::Write) => "write",
            Some(AccessLevel::Admin) => "admin",
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
    /// What the grant permits at all (Layer 1 ceiling).
    pub access_level: AccessLevel,
    /// What the grant permits *without a human in the loop*. `None` means
    /// never auto-approve. Invariant, enforced at the API boundary and by a
    /// DB `CHECK`: `auto_approve_level <= access_level`.
    pub auto_approve_level: Option<AccessLevel>,
}

/// Result of a group ceiling check.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupCeilingResult {
    /// Within the ceiling. `auto_approved` is true when a matching grant's
    /// `auto_approve_level` covers the action's risk — callers should skip
    /// Layer 2 (no permission rule written, no approval filed).
    WithinCeiling { auto_approved: bool },
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
///
/// Auto-approval rides the *same* ladder as a second, independently-set
/// ceiling: `auto_approve_level = read` reproduces the old
/// `auto_approve_reads` boolean, `write` also frees writes, `admin` frees
/// deletes too. There is no risk-shaped guard here any more — the level
/// itself decides.
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

    // Auto-approval: any matching grant whose auto-approve level covers the
    // risk. Independent of which grant supplied the access-level permission —
    // both columns already take the most-permissive-wins rule.
    let auto_approved = matching
        .iter()
        .any(|g| g.auto_approve_level.is_some_and(|l| l.permits_risk(risk)));

    GroupCeilingResult::WithinCeiling { auto_approved }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Group Ceiling tests ──────────────────────────────────────────

    fn grant(service: &str, level: AccessLevel, auto: Option<AccessLevel>) -> CeilingGrant {
        CeilingGrant {
            service_name: service.to_string(),
            access_level: level,
            auto_approve_level: auto,
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
        let grants = vec![grant("github", AccessLevel::Read, None)];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn ceiling_write_denied_by_read_grant() {
        let grants = vec![grant("github", AccessLevel::Read, None)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_write_allowed_by_write_grant() {
        let grants = vec![grant("github", AccessLevel::Write, None)];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn ceiling_delete_denied_by_write_grant() {
        let grants = vec![grant("github", AccessLevel::Write, None)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_delete_allowed_by_admin_grant() {
        let grants = vec![grant("github", AccessLevel::Admin, None)];
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn ceiling_service_not_granted() {
        let grants = vec![grant("slack", AccessLevel::Write, None)];
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
        let grants = vec![grant("http", AccessLevel::Admin, None)];
        assert_eq!(
            check_group_ceiling("http", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
        assert_eq!(
            check_group_ceiling("http", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn ceiling_http_write_denied_by_read_grant() {
        // A read-level http grant permits only GET/HEAD/OPTIONS (Risk::Read).
        let grants = vec![grant("http", AccessLevel::Read, None)];
        assert_eq!(
            check_group_ceiling("http", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
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

    // ── Auto-approve level ───────────────────────────────────────────

    #[test]
    fn auto_approve_read_level_covers_reads() {
        let grants = vec![grant("github", AccessLevel::Write, Some(AccessLevel::Read))];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: true
            },
        );
    }

    #[test]
    fn auto_approve_read_level_does_not_cover_writes() {
        let grants = vec![grant("github", AccessLevel::Write, Some(AccessLevel::Read))];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn auto_approve_write_level_covers_writes_not_deletes() {
        let grants = vec![grant(
            "github",
            AccessLevel::Admin,
            Some(AccessLevel::Write),
        )];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: true
            },
        );
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn auto_approve_admin_level_covers_deletes() {
        let grants = vec![grant(
            "github",
            AccessLevel::Admin,
            Some(AccessLevel::Admin),
        )];
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: true
            },
        );
    }

    #[test]
    fn auto_approve_none_never_bypasses() {
        let grants = vec![grant("github", AccessLevel::Admin, None)];
        for risk in [Risk::Read, Risk::Write, Risk::Delete] {
            assert_eq!(
                check_group_ceiling("github", risk, &grants, true),
                GroupCeilingResult::WithinCeiling {
                    auto_approved: false
                },
            );
        }
    }

    #[test]
    fn ceiling_most_permissive_grant_wins() {
        // Two groups: one with read, one with admin
        let grants = vec![
            grant("github", AccessLevel::Read, None),
            grant("github", AccessLevel::Admin, None),
        ];
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn ceiling_auto_approve_from_any_grant() {
        // One grant without auto-approve, one with
        let grants = vec![
            grant("github", AccessLevel::Write, None),
            grant("github", AccessLevel::Read, Some(AccessLevel::Read)),
        ];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: true
            },
        );
    }

    #[test]
    fn auto_approve_across_grants_does_not_exceed_own_ceiling() {
        // A read-level grant can only ever carry a read-level auto-approve
        // (the API and a DB CHECK enforce it), so a write on this service
        // still needs the write grant's own — absent — auto-approval.
        let grants = vec![
            grant("github", AccessLevel::Write, None),
            grant("github", AccessLevel::Read, Some(AccessLevel::Read)),
        ];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, true),
            GroupCeilingResult::WithinCeiling {
                auto_approved: false
            },
        );
    }

    #[test]
    fn access_level_parse() {
        assert_eq!(AccessLevel::parse("read"), Some(AccessLevel::Read));
        assert_eq!(AccessLevel::parse("write"), Some(AccessLevel::Write));
        assert_eq!(AccessLevel::parse("admin"), Some(AccessLevel::Admin));
        assert_eq!(AccessLevel::parse("invalid"), None);
        assert_eq!(AccessLevel::parse("none"), None);
    }

    #[test]
    fn auto_level_parse_and_render_round_trip() {
        assert_eq!(AccessLevel::parse_auto("none"), Some(None));
        assert_eq!(
            AccessLevel::parse_auto("write"),
            Some(Some(AccessLevel::Write))
        );
        assert_eq!(AccessLevel::parse_auto("nope"), None);
        for level in [
            None,
            Some(AccessLevel::Read),
            Some(AccessLevel::Write),
            Some(AccessLevel::Admin),
        ] {
            assert_eq!(
                AccessLevel::parse_auto(AccessLevel::render_auto(level)),
                Some(level)
            );
        }
    }

    #[test]
    fn permits_level_bounds_auto_approve_by_access() {
        assert!(AccessLevel::Admin.permits_level(AccessLevel::Admin));
        assert!(AccessLevel::Write.permits_level(AccessLevel::Read));
        assert!(!AccessLevel::Read.permits_level(AccessLevel::Write));
        assert!(!AccessLevel::Write.permits_level(AccessLevel::Admin));
    }
}
