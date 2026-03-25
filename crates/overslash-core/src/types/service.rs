use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A service definition — describes an external API, its auth methods, and available actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub key: String,
    pub display_name: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub auth: Vec<ServiceAuth>,
    #[serde(default)]
    pub actions: HashMap<String, ServiceAction>,
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
    #[serde(default = "default_risk")]
    pub risk: String,
    #[serde(default)]
    pub params: HashMap<String, ActionParam>,
}

fn default_risk() -> String {
    "read".into()
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
