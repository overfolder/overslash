//! Platform kernels for service-instance CRUD.
//!
//! These mirror `platform_templates.rs`: pure async functions that take a
//! [`PlatformCallContext`] plus typed inputs and return a typed response.
//! Both the REST handlers in `routes/services.rs` and the MCP platform
//! dispatcher (via `platform_registry`) call into the same kernel — this
//! keeps the auto-add-to-Myself behavior, owner resolution, template
//! validation, and credential-status derivation in one place.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_core::types::{
    McpAuth, Runtime, SecretSource, ServiceAction, ServiceAuth, ServiceDefinition,
};
use overslash_db::repos::group::ServiceGroupRow;
use overslash_db::repos::org as org_repo;
use overslash_db::repos::service_instance::{
    ConfigMap, CreateServiceInstance, CredentialsMap, ServiceInstanceRow, UpdateServiceInstance,
};
use overslash_db::repos::service_template;
use overslash_db::scopes::{OrgScope, UserScope};

use super::group_ceiling;
use super::platform_caller::PlatformCallContext;
use crate::error::AppError;
use crate::routes::util::fmt_time;

mod group_grants;
mod kernels;
mod reconcile;
mod rows;
mod status;
mod templates;
mod types;

pub use kernels::{
    kernel_create_service, kernel_get_service, kernel_list_services, kernel_update_service,
};
pub use rows::{row_to_detail, row_to_summary};
pub use status::{
    ScopeCoverage, ScopeKnowledge, action_scope_coverage, compute_credentials_status,
    derive_credentials_status, resolve_instance_icon_url,
};
pub use templates::{resolve_template_definition, resolve_template_source};
pub use types::{
    ConnectBundle, CreateServiceGroupGrant, CreateServiceInput, CredentialsStatus, GetServiceInput,
    ServiceGroupRef, ServiceInstanceDetail, ServiceInstanceSummary, UpdateServiceInput,
};

pub(crate) use status::resolve_effective_scopes;
pub(crate) use templates::template_oauth_provider;

/// Map a *present* connection's optional scopes to [`ScopeKnowledge`]. Call
/// sites that reach here have already established the connection exists, so
/// `None` scopes means "recorded as unknown", not "no connection".
fn scope_knowledge(scopes: Option<&[String]>) -> ScopeKnowledge<'_> {
    match scopes {
        Some(s) => ScopeKnowledge::Known(s),
        None => ScopeKnowledge::Unknown,
    }
}

/// Fixtures shared by the sibling modules' test blocks.
#[cfg(test)]
mod test_fixtures {
    use super::*;
    use overslash_core::types::{McpSpec, Risk, ServiceAction, TokenInjection};
    use std::collections::HashMap;

    pub(super) fn mcp_bearer_template(default_secret: Option<&str>) -> ServiceDefinition {
        ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            icon: None,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://example.com".into()),
                auth: McpAuth::Bearer {
                    secret_name: default_secret.map(|s| s.to_string()),
                },
                autodiscover: false,
            }),
            instance_defaults: None,
        }
    }

    pub(super) fn mcp_oauth_template(provider: &str, scopes: &[&str]) -> ServiceDefinition {
        ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            icon: None,
            auth: vec![],
            // MCP tools carry no per-action required_scopes; scopes live on the
            // service-level oauth block.
            actions: HashMap::new(),
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://mcp.example.com/mcp".into()),
                auth: McpAuth::OAuth {
                    provider: provider.to_string(),
                    scopes: scopes.iter().map(|s| s.to_string()).collect(),
                },
                autodiscover: false,
            }),
            instance_defaults: None,
        }
    }

    pub(super) fn secret_template() -> ServiceDefinition {
        ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            icon: None,
            auth: vec![ServiceAuth::Secret {
                template: None,
                slots: Vec::new(),
                config_keys: Vec::new(),
                scheme: String::new(),
                label: String::new(),
                description: String::new(),
                default_secret_name: "default".into(),
                injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
                secret_source: overslash_core::types::SecretSource::Instance,
                optional: false,
            }],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    pub(super) fn oauth_template(actions: Vec<(&str, Vec<&str>)>) -> ServiceDefinition {
        let mut map = HashMap::new();
        for (key, required) in actions {
            map.insert(
                key.to_string(),
                ServiceAction {
                    timeout_ms: None,
                    method: "GET".into(),
                    path: "/".into(),
                    description: String::new(),
                    summary: None,
                    risk: Risk::Read.into(),
                    response_type: None,
                    params: HashMap::new(),
                    scope_param: Default::default(),
                    required_scopes: required.iter().map(|s| s.to_string()).collect(),
                    permission: None,
                    disclose: Vec::new(),
                    redact: Vec::new(),
                    mcp_tool: None,
                    output_schema: None,
                    disabled: false,
                    request_body: None,
                    download: None,
                },
            );
        }
        ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            icon: None,
            auth: vec![ServiceAuth::OAuth {
                provider: "google".into(),
                scopes: vec![],
                token_injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
            }],
            actions: map,
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    pub(super) fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    /// email.yaml-shaped auth: an optional org-source `gateway` slot plus a
    /// required instance-source `mailbox` slot.
    pub(super) fn dual_scheme_template() -> ServiceDefinition {
        let mut tpl = secret_template();
        let injection = TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: Some("Bearer ".into()),
        };
        tpl.auth = vec![
            ServiceAuth::Secret {
                template: None,
                slots: Vec::new(),
                config_keys: Vec::new(),
                scheme: "gateway".into(),
                label: String::new(),
                description: String::new(),
                default_secret_name: "overfwd_gateway_key".into(),
                injection: injection.clone(),
                secret_source: overslash_core::types::SecretSource::Org,
                optional: true,
            },
            ServiceAuth::Secret {
                template: None,
                slots: Vec::new(),
                config_keys: Vec::new(),
                scheme: "mailbox".into(),
                label: String::new(),
                description: String::new(),
                default_secret_name: "mailbox_credential".into(),
                injection,
                secret_source: overslash_core::types::SecretSource::Instance,
                optional: false,
            },
        ];
        tpl
    }
}
