//! Per-instance config — the non-secret pins a template declares with
//! `x-overslash-instance-config`.
//!
//! Two writers need the identical rules, so they live here rather than in
//! either caller:
//!
//! - a **service instance** pinning values for itself (`service_instances.config`)
//! - an **org layer** supplying defaults every instance inherits
//!   ([`crate::service_layer::InstanceDefaults`])
//!
//! Only params the template marks `x-overslash-instance-config` may be pinned.
//! The alternative — accepting any key — would let a writer pin an arbitrary
//! request parameter on every call the instance ever makes, which is a
//! permissions surface, not a convenience: `risk`/`disclose` are authored per
//! action against the params a *caller* supplies.
//!
//! Blank values are rejected rather than stored, so "unset" has one
//! representation (key absent) instead of two.

use std::collections::BTreeMap;

use crate::types::ServiceDefinition;

/// Pinned `{param name → value}`. Values are stored as strings and cast by the
/// executor's `coerce_args` against the param's declared type.
///
/// Structurally identical to `overslash_db::repos::service_instance::ConfigMap`,
/// so the two interoperate without conversion.
pub type ConfigMap = BTreeMap<String, String>;

/// Why a config map was rejected. Callers render this into their own error
/// shape — `AppError::BadRequest` for the instance write path, a
/// [`crate::template_validation::ValidationIssue`] for the layer write path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A key no action of the template declares as instance-configurable.
    UnknownKey { key: String, declared: Vec<String> },
    /// A key present with an empty (or whitespace-only) value.
    BlankValue { key: String },
}

impl ConfigError {
    /// The offending key, for use as a validation issue's `path`.
    pub fn key(&self) -> &str {
        match self {
            ConfigError::UnknownKey { key, .. } | ConfigError::BlankValue { key } => key,
        }
    }

    /// A stable error code, for use as a validation issue's `code`.
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::UnknownKey { .. } => "unknown_instance_config",
            ConfigError::BlankValue { .. } => "blank_instance_config",
        }
    }

    /// Human-readable message. `template_key` names the template whose declared
    /// keys were consulted.
    pub fn message(&self, template_key: &str) -> String {
        match self {
            ConfigError::UnknownKey { key, declared } => format!(
                "unknown instance config '{key}'; template '{template_key}' declares: {}",
                if declared.is_empty() {
                    "none".to_string()
                } else {
                    declared.join(", ")
                }
            ),
            ConfigError::BlankValue { key } => {
                format!("instance config '{key}' must have a value; omit the key to unset it")
            }
        }
    }
}

/// Every param name across `def`'s actions declared `x-overslash-instance-config`,
/// sorted and deduped. A param may appear on several actions (the `email`
/// mailbox-endpoint headers are a shared YAML anchor); one entry is emitted.
pub fn configurable_keys(def: &ServiceDefinition) -> Vec<String> {
    let mut keys: Vec<String> = def
        .actions
        .values()
        .flat_map(|a| a.params.iter())
        .filter(|(_, p)| p.instance_config)
        .map(|(name, _)| name.clone())
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Validate `explicit` against what `def` declares, returning the normalized map
/// to store (values trimmed). Fails on the first offending key so the writer
/// gets one actionable message.
pub fn validate_config(
    def: &ServiceDefinition,
    explicit: &ConfigMap,
) -> Result<ConfigMap, ConfigError> {
    let declared = configurable_keys(def);

    let mut map = ConfigMap::new();
    for (key, value) in explicit {
        if !declared.contains(key) {
            return Err(ConfigError::UnknownKey {
                key: key.clone(),
                declared,
            });
        }
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::BlankValue { key: key.clone() });
        }
        map.insert(key.clone(), trimmed.to_string());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActionParam, ParamLocation, Risk, ServiceAction};
    use std::collections::HashMap;

    fn param(instance_config: bool) -> ActionParam {
        ActionParam {
            param_type: "string".into(),
            required: false,
            description: String::new(),
            enum_values: None,
            default: None,
            resolve: None,
            aliases: vec![],
            location: ParamLocation::Header,
            instance_config,
        }
    }

    fn def_with(params: &[(&str, bool)]) -> ServiceDefinition {
        let mut action = ServiceAction {
            method: "GET".into(),
            path: "/x".into(),
            description: "x".into(),
            risk: Risk::Read,
            response_type: None,
            params: HashMap::new(),
            scope_param: None,
            required_scopes: vec![],
            permission: None,
            disclose: vec![],
            redact: vec![],
            mcp_tool: None,
            output_schema: None,
            disabled: false,
        };
        for (name, instance_config) in params {
            action
                .params
                .insert((*name).to_string(), param(*instance_config));
        }
        ServiceDefinition {
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec!["api.example.com".into()],
            category: None,
            hidden: false,
            auth: vec![],
            secrets: vec![],
            actions: HashMap::from([("a".to_string(), action)]),
            runtime: crate::types::Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    #[test]
    fn declared_keys_are_sorted_and_deduped() {
        let def = def_with(&[("X-B", true), ("X-A", true), ("X-C", false)]);
        assert_eq!(configurable_keys(&def), vec!["X-A", "X-B"]);
    }

    #[test]
    fn undeclared_key_is_rejected() {
        let def = def_with(&[("X-A", true)]);
        let explicit = ConfigMap::from([("X-Z".to_string(), "v".to_string())]);
        let err = validate_config(&def, &explicit).unwrap_err();
        assert_eq!(err.code(), "unknown_instance_config");
        assert!(err.message("t").contains("declares: X-A"));
    }

    #[test]
    fn blank_value_is_rejected_and_values_are_trimmed() {
        let def = def_with(&[("X-A", true)]);
        let blank = ConfigMap::from([("X-A".to_string(), "   ".to_string())]);
        assert_eq!(
            validate_config(&def, &blank).unwrap_err().code(),
            "blank_instance_config"
        );

        let padded = ConfigMap::from([("X-A".to_string(), "  imap.acme.com  ".to_string())]);
        assert_eq!(
            validate_config(&def, &padded).unwrap()["X-A"],
            "imap.acme.com"
        );
    }
}
