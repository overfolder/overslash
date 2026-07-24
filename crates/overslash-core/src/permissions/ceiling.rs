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
