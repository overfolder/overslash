use std::fmt;

use serde::{Deserialize, Serialize};

/// Risk level of a service action: read, write, or delete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    #[default]
    Read,
    Write,
    Delete,
}

impl Risk {
    /// Returns `true` for write and delete operations.
    pub fn is_mutating(self) -> bool {
        !matches!(self, Risk::Read)
    }

    /// Monotonic severity ordering: `read < write < delete`. Used by the
    /// layered-template fold to clamp risk **upward only** (a mask may add
    /// approvals, never remove them).
    pub fn severity(self) -> u8 {
        match self {
            Risk::Read => 0,
            Risk::Write => 1,
            Risk::Delete => 2,
        }
    }

    /// The more severe of two risks. Used to merge a call-time floor (e.g.
    /// the D42 SQL classifier's verdict) into a declared risk — elevation
    /// only, never a downgrade.
    pub fn max_severity(self, other: Risk) -> Risk {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }

    /// Infer risk from an HTTP method.
    pub fn from_http_method(method: &str) -> Risk {
        match method.to_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => Risk::Read,
            "DELETE" => Risk::Delete,
            _ => Risk::Write,
        }
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Risk::Read => write!(f, "read"),
            Risk::Write => write!(f, "write"),
            Risk::Delete => write!(f, "delete"),
        }
    }
}

/// The risk a template *declares* for an action: one of the three static
/// [`Risk`] classes, or `dynamic` — "classified per call from the SQL the
/// caller supplies" (D42/D43).
///
/// `dynamic` is only accepted by template validation on an action that
/// nominates an `x-overslash-sql-field` param, because without a nominated field
/// there is nothing to classify. At call time a dynamic action starts from
/// [`base_risk`](Self::base_risk) (`read`) and the classifier's verdict is
/// merged in as a floor — a build without the `sql_policy` feature classifies
/// everything as write, so the fast read path only exists where the parser
/// does. Static/display contexts use [`display_risk`](Self::display_risk)
/// (`write`): until a concrete query proves otherwise, a dynamic action is
/// presented as mutating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclaredRisk {
    #[default]
    Read,
    Write,
    Delete,
    Dynamic,
}

impl DeclaredRisk {
    pub fn is_dynamic(self) -> bool {
        matches!(self, DeclaredRisk::Dynamic)
    }

    /// The concrete risk for static contexts (listings, approval-card
    /// severity, the mutating-actions-declare-disclose gate, layer-fold
    /// severity comparisons): `dynamic` counts as **write** until a concrete
    /// query proves otherwise.
    pub fn display_risk(self) -> Risk {
        match self {
            DeclaredRisk::Read => Risk::Read,
            DeclaredRisk::Write => Risk::Write,
            DeclaredRisk::Delete => Risk::Delete,
            DeclaredRisk::Dynamic => Risk::Write,
        }
    }

    /// The call-time starting point *before* the SQL classifier's floor is
    /// merged in: `dynamic` starts at **read** and only stays there when the
    /// parse proves the statement read-only. Callers must always merge the
    /// classifier verdict (which fails closed to write) on top — this value
    /// alone never gates anything.
    pub fn base_risk(self) -> Risk {
        match self {
            DeclaredRisk::Dynamic => Risk::Read,
            other => other.display_risk(),
        }
    }
}

impl From<Risk> for DeclaredRisk {
    fn from(r: Risk) -> Self {
        match r {
            Risk::Read => DeclaredRisk::Read,
            Risk::Write => DeclaredRisk::Write,
            Risk::Delete => DeclaredRisk::Delete,
        }
    }
}

/// A declared risk equals a static [`Risk`] iff it is that static class;
/// `Dynamic` equals none of them. Lets call sites (and tests) compare
/// `action.risk == Risk::Write` without lifting.
impl PartialEq<Risk> for DeclaredRisk {
    fn eq(&self, other: &Risk) -> bool {
        *self == DeclaredRisk::from(*other)
    }
}

impl PartialEq<DeclaredRisk> for Risk {
    fn eq(&self, other: &DeclaredRisk) -> bool {
        other == self
    }
}

impl fmt::Display for DeclaredRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeclaredRisk::Dynamic => write!(f, "dynamic"),
            other => other.display_risk().fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_serde_roundtrip() {
        assert_eq!(serde_json::to_string(&Risk::Read).unwrap(), r#""read""#);
        assert_eq!(serde_json::to_string(&Risk::Write).unwrap(), r#""write""#);
        assert_eq!(serde_json::to_string(&Risk::Delete).unwrap(), r#""delete""#);

        assert_eq!(
            serde_json::from_str::<Risk>(r#""read""#).unwrap(),
            Risk::Read
        );
        assert_eq!(
            serde_json::from_str::<Risk>(r#""write""#).unwrap(),
            Risk::Write
        );
        assert_eq!(
            serde_json::from_str::<Risk>(r#""delete""#).unwrap(),
            Risk::Delete
        );
    }

    #[test]
    fn risk_default_is_read() {
        assert_eq!(Risk::default(), Risk::Read);
    }

    /// `DeclaredRisk` deserializes byte-compatibly with the pre-D43 `Risk`
    /// wire forms (pre-existing templates keep parsing) and adds `dynamic`.
    #[test]
    fn declared_risk_serde_and_semantics() {
        for (json, want) in [
            (r#""read""#, DeclaredRisk::Read),
            (r#""write""#, DeclaredRisk::Write),
            (r#""delete""#, DeclaredRisk::Delete),
            (r#""dynamic""#, DeclaredRisk::Dynamic),
        ] {
            assert_eq!(serde_json::from_str::<DeclaredRisk>(json).unwrap(), want);
            assert_eq!(serde_json::to_string(&want).unwrap(), json);
        }
        assert_eq!(DeclaredRisk::default(), DeclaredRisk::Read);

        // Static/display contexts see dynamic as write-until-proven-read…
        assert_eq!(DeclaredRisk::Dynamic.display_risk(), Risk::Write);
        // …while the call-time base starts at read for the classifier merge.
        assert_eq!(DeclaredRisk::Dynamic.base_risk(), Risk::Read);
        assert_eq!(DeclaredRisk::Delete.base_risk(), Risk::Delete);

        // Cross-type equality: a static class matches, dynamic matches none.
        assert_eq!(DeclaredRisk::Write, Risk::Write);
        assert_ne!(DeclaredRisk::Dynamic, Risk::Write);
    }

    #[test]
    fn risk_is_mutating() {
        assert!(!Risk::Read.is_mutating());
        assert!(Risk::Write.is_mutating());
        assert!(Risk::Delete.is_mutating());
    }

    #[test]
    fn risk_from_http_method() {
        assert_eq!(Risk::from_http_method("GET"), Risk::Read);
        assert_eq!(Risk::from_http_method("HEAD"), Risk::Read);
        assert_eq!(Risk::from_http_method("OPTIONS"), Risk::Read);
        assert_eq!(Risk::from_http_method("POST"), Risk::Write);
        assert_eq!(Risk::from_http_method("PUT"), Risk::Write);
        assert_eq!(Risk::from_http_method("PATCH"), Risk::Write);
        assert_eq!(Risk::from_http_method("DELETE"), Risk::Delete);
        // case-insensitive
        assert_eq!(Risk::from_http_method("get"), Risk::Read);
        assert_eq!(Risk::from_http_method("delete"), Risk::Delete);
    }

    #[test]
    fn risk_display() {
        assert_eq!(Risk::Read.to_string(), "read");
        assert_eq!(Risk::Write.to_string(), "write");
        assert_eq!(Risk::Delete.to_string(), "delete");
    }
}
