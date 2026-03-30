use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Resource types that can be controlled via ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclResourceType {
    Services,
    Connections,
    Secrets,
    Agents,
    Approvals,
    AuditLogs,
    Webhooks,
    OrgSettings,
    Acl,
}

impl AclResourceType {
    pub const ALL: &'static [AclResourceType] = &[
        Self::Services,
        Self::Connections,
        Self::Secrets,
        Self::Agents,
        Self::Approvals,
        Self::AuditLogs,
        Self::Webhooks,
        Self::OrgSettings,
        Self::Acl,
    ];
}

impl fmt::Display for AclResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Services => write!(f, "services"),
            Self::Connections => write!(f, "connections"),
            Self::Secrets => write!(f, "secrets"),
            Self::Agents => write!(f, "agents"),
            Self::Approvals => write!(f, "approvals"),
            Self::AuditLogs => write!(f, "audit_logs"),
            Self::Webhooks => write!(f, "webhooks"),
            Self::OrgSettings => write!(f, "org_settings"),
            Self::Acl => write!(f, "acl"),
        }
    }
}

impl FromStr for AclResourceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "services" => Ok(Self::Services),
            "connections" => Ok(Self::Connections),
            "secrets" => Ok(Self::Secrets),
            "agents" => Ok(Self::Agents),
            "approvals" => Ok(Self::Approvals),
            "audit_logs" => Ok(Self::AuditLogs),
            "webhooks" => Ok(Self::Webhooks),
            "org_settings" => Ok(Self::OrgSettings),
            "acl" => Ok(Self::Acl),
            other => Err(format!("unknown resource type: {other}")),
        }
    }
}

/// Actions that can be granted on a resource type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    Read,
    Write,
    Delete,
    Manage,
}

impl AclAction {
    /// Returns true if `self` implies the `other` action.
    /// `Manage` implies all other actions.
    pub fn implies(&self, other: &AclAction) -> bool {
        if self == other {
            return true;
        }
        matches!(self, AclAction::Manage)
    }

    pub const ALL: &'static [AclAction] = &[Self::Read, Self::Write, Self::Delete, Self::Manage];
}

impl fmt::Display for AclAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Delete => write!(f, "delete"),
            Self::Manage => write!(f, "manage"),
        }
    }
}

impl FromStr for AclAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "delete" => Ok(Self::Delete),
            "manage" => Ok(Self::Manage),
            other => Err(format!("unknown action: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manage_implies_all() {
        assert!(AclAction::Manage.implies(&AclAction::Read));
        assert!(AclAction::Manage.implies(&AclAction::Write));
        assert!(AclAction::Manage.implies(&AclAction::Delete));
        assert!(AclAction::Manage.implies(&AclAction::Manage));
    }

    #[test]
    fn non_manage_only_implies_self() {
        assert!(AclAction::Read.implies(&AclAction::Read));
        assert!(!AclAction::Read.implies(&AclAction::Write));
        assert!(!AclAction::Write.implies(&AclAction::Delete));
    }

    #[test]
    fn resource_type_roundtrip() {
        for rt in AclResourceType::ALL {
            let s = rt.to_string();
            let parsed: AclResourceType = s.parse().unwrap();
            assert_eq!(*rt, parsed);
        }
    }

    #[test]
    fn action_roundtrip() {
        for a in AclAction::ALL {
            let s = a.to_string();
            let parsed: AclAction = s.parse().unwrap();
            assert_eq!(*a, parsed);
        }
    }
}
