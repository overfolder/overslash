//! Shared fixture builders for the `validate_input` unit tests.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::ActionParam;

pub(super) fn p(t: &str, required: bool) -> ActionParam {
    ActionParam {
        param_type: t.into(),
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

pub(super) fn p_alias(t: &str, required: bool, aliases: &[&str]) -> ActionParam {
    ActionParam {
        aliases: aliases.iter().map(|s| s.to_string()).collect(),
        ..p(t, required)
    }
}

pub(super) fn p_default(t: &str, required: bool, default: Value) -> ActionParam {
    ActionParam {
        default: Some(default),
        ..p(t, required)
    }
}

pub(super) fn p_enum(members: &[&str], required: bool) -> ActionParam {
    ActionParam {
        enum_values: Some(members.iter().map(|s| s.to_string()).collect()),
        ..p("string", required)
    }
}

pub(super) fn schema(entries: &[(&str, ActionParam)]) -> HashMap<String, ActionParam> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

pub(super) fn args(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}
