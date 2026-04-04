use std::collections::HashMap;
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

/// A service definition — describes an external API, its auth methods, and available actions.
/// Also referred to as a "service template" (the blueprint from which service instances are created).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub key: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default)]
    pub auth: Vec<ServiceAuth>,
    #[serde(default)]
    pub actions: HashMap<String, ServiceAction>,
}

/// Alias: a service template is the same as a service definition.
pub type ServiceTemplate = ServiceDefinition;

/// Which tier a template belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateTier {
    Global,
    Org,
    User,
}

/// Auth method supported by a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServiceAuth {
    #[serde(rename = "oauth")]
    OAuth {
        provider: String,
        token_injection: TokenInjection,
    },
    #[serde(rename = "api_key")]
    ApiKey {
        default_secret_name: String,
        injection: TokenInjection,
    },
}

/// How to inject a token/key into the HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInjection {
    #[serde(rename = "as")]
    pub inject_as: String, // "header" or "query"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// An action within a service (maps to an HTTP request template).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAction {
    pub method: String,
    pub path: String,
    pub description: String,
    #[serde(default)]
    pub risk: Risk,
    /// Response type hint: "json" (default) or "binary" (for file downloads).
    /// When "binary", callers should use `prefer_stream: true` to avoid buffering.
    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, ActionParam>,
}

/// A parameter for a service action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParam {
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
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
