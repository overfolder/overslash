//! WASM-safe struct-level validator. Pure function over a parsed
//! [`ServiceDefinition`]. No YAML, no `serde_json` deserialization, no I/O.
//!
//! The full rule set is documented inline and mirrored in SPEC.md §9.

use std::collections::HashSet;

use crate::template_validation::{Issues, ValidationReport};
use crate::types::{Runtime, ServiceDefinition};

mod action;
mod auth;
mod mcp;
mod resolver;
pub(crate) mod service_shape;
mod sql_policy;

use action::{check_action, check_platform_action};
use auth::check_auth;
use mcp::check_mcp;
use resolver::check_resolver_targets;
use service_shape::check_service_shape;

/// Validate a parsed [`ServiceDefinition`].
///
/// `raw_action_keys` is the in-order list of action keys as they appeared in
/// the source document. The YAML entry point supplies this from a raw YAML
/// walk; callers with already-deduped input (JSON, a typed struct built
/// programmatically) can pass an empty slice to skip duplicate-key detection.
pub fn validate_service_definition(
    def: &ServiceDefinition,
    raw_action_keys: &[String],
) -> ValidationReport {
    let mut issues = Issues::default();

    check_service_shape(def, &mut issues);
    if def.runtime != Runtime::Platform {
        check_auth(def, &mut issues);
    }
    check_mcp(def, &mut issues);
    check_duplicate_action_keys(raw_action_keys, &mut issues);
    check_resolver_targets(def, &mut issues);

    // Iterate actions in a deterministic order so test assertions can match
    // on issue order when needed.
    let mut action_keys: Vec<&String> = def.actions.keys().collect();
    action_keys.sort();
    for key in action_keys {
        let action = &def.actions[key];
        if def.runtime == Runtime::Platform {
            check_platform_action(key, action, &mut issues);
        } else {
            check_action(key, action, &mut issues);
        }
    }

    issues.finish()
}

// --- duplicate action keys -------------------------------------------------

fn check_duplicate_action_keys(raw_keys: &[String], issues: &mut Issues) {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut reported: HashSet<&str> = HashSet::new();
    for k in raw_keys {
        if !seen.insert(k.as_str()) && reported.insert(k.as_str()) {
            issues.err(
                "duplicate_action_key",
                format!("action key {k:?} is defined more than once"),
                format!("actions.{k}"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ActionParam, McpAuth, Risk, SecretSource, ServiceAction, ServiceAuth, ServiceDefinition,
        TokenInjection,
    };
    use std::collections::HashMap;

    pub(super) fn minimal_valid() -> ServiceDefinition {
        ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "svc".into(),
            display_name: "Service".into(),
            description: None,
            hosts: vec!["api.example.com".into()],
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
                default_secret_name: "svc_token".into(),
                injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
                secret_source: SecretSource::Instance,
                optional: false,
            }],
            actions: {
                let mut m = HashMap::new();
                m.insert(
                    "list".into(),
                    ServiceAction {
                        wait_mode: None,
                        handoff_after_ms: None,
                        timeout_ms: None,
                        method: "GET".into(),
                        path: "/items".into(),
                        description: "List items".into(),
                        summary: None,
                        risk: Risk::Read.into(),
                        response_type: None,
                        params: HashMap::new(),
                        scope_param: Default::default(),
                        required_scopes: Vec::new(),
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
                m
            },
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    pub(super) fn param(ty: &str, required: bool) -> ActionParam {
        ActionParam {
            param_type: ty.into(),
            required,
            description: String::new(),
            enum_values: None,
            default: None,
            resolve: None,
            aliases: Vec::new(),
            location: crate::types::ParamLocation::Body,
            instance_config: false,
            sql_field: None,
            sql_database: None,
        }
    }

    pub(super) fn run(def: &ServiceDefinition) -> ValidationReport {
        validate_service_definition(def, &[])
    }

    #[test]
    fn happy_path_valid() {
        let report = run(&minimal_valid());
        assert!(report.valid, "errors: {:?}", report.errors);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn duplicate_action_key() {
        let d = minimal_valid();
        let report =
            validate_service_definition(&d, &["list".into(), "other".into(), "list".into()]);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "duplicate_action_key")
        );
    }

    pub(super) fn minimal_mcp(auth: McpAuth) -> ServiceDefinition {
        use crate::types::McpSpec;
        let mut actions = HashMap::new();
        actions.insert(
            "search".into(),
            ServiceAction {
                wait_mode: None,
                handoff_after_ms: None,
                timeout_ms: None,
                method: String::new(),
                path: String::new(),
                description: "Search {team}".into(),
                summary: None,
                risk: Risk::Read.into(),
                response_type: None,
                params: {
                    let mut p = HashMap::new();
                    p.insert(
                        "team".into(),
                        ActionParam {
                            param_type: "string".into(),
                            required: true,
                            description: String::new(),
                            enum_values: None,
                            default: None,
                            resolve: None,
                            aliases: Vec::new(),
                            location: crate::types::ParamLocation::Body,
                            instance_config: false,
                            sql_field: None,
                            sql_database: None,
                        },
                    );
                    p
                },
                scope_param: "team".into(),
                required_scopes: vec![],
                permission: None,
                disclose: vec![],
                redact: vec![],
                mcp_tool: Some("search".into()),
                output_schema: None,
                disabled: false,
                request_body: None,
                download: None,
            },
        );
        ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "linear_mcp".into(),
            display_name: "Linear".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            icon: None,
            auth: vec![],
            actions,
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://mcp.linear.app/mcp".into()),
                auth,
                autodiscover: true,
            }),
            instance_defaults: None,
        }
    }
}
