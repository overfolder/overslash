use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A secret reference for injection into an HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    pub name: String,
    pub inject_as: InjectAs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectAs {
    Header,
    Query,
}

/// A raw HTTP action request (Mode A).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
}

/// Result of executing an HTTP action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
}
