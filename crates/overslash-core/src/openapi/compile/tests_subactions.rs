//! Compile-time tests for `x-overslash-subactions`: parsing, the actions a
//! callable variant compiles to, and the shapes that are refused.

use super::*;
use crate::openapi::normalize_aliases;
use crate::types::{DeclaredRisk, Risk};
use serde_json::json;

fn mcp_doc(tool_extra: Value) -> Value {
    let mut tool = json!({
        "name": "manage_crm_objects",
        "risk": "write",
        "description": "Create or update CRM records",
        "input_schema": {"type": "object", "properties": {
            "createRequest": {"type": "object"},
            "updateRequest": {"type": "object"}
        }}
    });
    for (k, v) in tool_extra.as_object().unwrap() {
        tool[k] = v.clone();
    }
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Crm", "key": "crm"},
        "x-overslash-runtime": "mcp",
        "servers": [],
        "paths": {},
        "x-overslash-mcp": {
            "url": "https://mcp.crm.example",
            "auth": {"kind": "none"},
            "autodiscover": false,
            "tools": [tool]
        }
    })
}

fn compile(mut doc: Value) -> Result<ServiceDefinition, Vec<ValidationIssue>> {
    normalize_aliases(&mut doc);
    compile_service(&doc).map(|(d, _)| d)
}

fn create_contact() -> Value {
    json!({
        "name": "create_contact",
        "match": ".op == \"create\" and .objectType == \"contacts\"",
        "description": "Create a contact",
        "verb": "create",
        "phrase": "contact {item.label}",
        "vars": {"label": ".properties.email"},
        "input_schema": {"type": "object", "properties": {
            "properties": {"type": "object"}
        }, "required": ["properties"]},
        "transform": "{createRequest: {objects: [{objectType: \"contacts\", properties: .properties}]}}"
    })
}

#[test]
fn the_unprefixed_block_parses_and_a_callable_variant_becomes_an_action() {
    let svc = compile(mcp_doc(json!({"subactions": {
        "each": "(.createRequest.objects[]? | . + {op: \"create\"})",
        "variants": [
            create_contact(),
            {"name": "create_note", "match": ".objectType == \"notes\"", "risk": "read"}
        ]
    }})))
    .unwrap();
    let parent = &svc.actions["manage_crm_objects"];
    let spec = parent.subactions.as_ref().unwrap();
    assert_eq!(spec.variants.len(), 2);
    assert_eq!(
        spec.variants[0].risk,
        Risk::Write,
        "inherits the parent's risk"
    );
    assert_eq!(spec.variants[1].risk, Risk::Read);
    assert!(spec.variants[0].is_callable());
    assert!(!spec.variants[1].is_callable());

    let callable = &svc.actions["create_contact"];
    let of = callable.subaction_of.as_ref().unwrap();
    assert_eq!(
        (of.parent.as_str(), of.variant.as_str()),
        ("manage_crm_objects", "create_contact")
    );
    assert_eq!(callable.mcp_tool.as_deref(), Some("manage_crm_objects"));
    assert_eq!(callable.risk, DeclaredRisk::Write);
    assert!(callable.params["properties"].required);
    assert!(callable.subactions.is_none());
    assert!(
        !svc.actions.contains_key("create_note"),
        "only callable variants are actions"
    );
}

#[test]
fn a_callable_variant_may_not_shadow_another_action() {
    let mut doc = mcp_doc(json!({"subactions": {"variants": [
        {"name": "manage_crm_objects", "match": "true",
         "input_schema": {"type": "object", "properties": {}}, "transform": "."}
    ]}}));
    normalize_aliases(&mut doc);
    let errs = compile(doc).unwrap_err();
    assert!(
        errs.iter().any(|e| e.code == "subactions_key_collision"),
        "{errs:?}"
    );
}

#[test]
fn malformed_blocks_are_refused_with_a_reason() {
    let cases = [
        (
            json!({"subactions": {"variants": []}}),
            "subactions_malformed",
        ),
        (
            json!({"subactions": {"variants": [{"name": "x", "match": "true", "bogus": 1}]}}),
            "subactions_malformed",
        ),
        (
            json!({"subactions": {"variants": [{"name": "Bad-Name", "match": "true"}]}}),
            "subactions_malformed",
        ),
        (
            json!({"subactions": {"variants": [{"name": "x"}]}}),
            "subactions_malformed",
        ),
        (
            json!({"subactions": {"variants": [{"name": "x", "match": "true", "transform": "."}]}}),
            "subactions_malformed",
        ),
        (
            json!({"subactions": {"variants": [{"name": "x", "match": "true", "risk": "dynamic"}]}}),
            "invalid_risk",
        ),
        (
            json!({"subactions": {"variants": [
                {"name": "x", "match": "true"}, {"name": "x", "match": "false"}
            ]}}),
            "subactions_duplicate_variant",
        ),
        (
            json!({"risk": "dynamic", "subactions": {"variants": [{"name": "x", "match": "true"}]}}),
            "subactions_on_dynamic_risk",
        ),
    ];
    for (extra, code) in cases {
        let errs = compile(mcp_doc(extra.clone())).expect_err(&extra.to_string());
        assert!(
            errs.iter().any(|e| e.code == code),
            "{extra}: wanted {code}, got {errs:?}"
        );
    }
}

#[test]
fn an_http_operation_carries_subactions_too() {
    let svc = compile(json!({
        "openapi": "3.1.0",
        "info": {"title": "Batch", "key": "batch"},
        "servers": [{"url": "https://batch.example"}],
        "paths": {"/batch": {"post": {
            "operationId": "batch",
            "description": "Run a batch",
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object", "properties": {"ops": {"type": "array"}}
            }}}},
            "subactions": {"each": ".ops[]", "variants": [{
                "name": "delete_thing", "match": ".kind == \"delete\"", "risk": "delete",
                "input_schema": {"type": "object", "properties": {"id": {"type": "string"}}},
                "transform": "{ops: [{kind: \"delete\", id: .id}]}"
            }]}
        }}}
    }))
    .unwrap();
    let callable = &svc.actions["delete_thing"];
    assert_eq!(
        (callable.method.as_str(), callable.path.as_str()),
        ("POST", "/batch")
    );
    assert_eq!(callable.risk, DeclaredRisk::Delete);
    assert!(callable.request_body.is_some());
}

#[test]
fn the_spec_round_trips_through_serde() {
    let svc = compile(mcp_doc(
        json!({"subactions": {"variants": [create_contact()]}}),
    ))
    .unwrap();
    let wire = serde_json::to_value(&svc).unwrap();
    let back: ServiceDefinition = serde_json::from_value(wire).unwrap();
    let spec = back.actions["manage_crm_objects"]
        .subactions
        .as_ref()
        .unwrap();
    assert_eq!(
        spec.variants[0].matches,
        ".op == \"create\" and .objectType == \"contacts\""
    );
    assert_eq!(
        back.actions["create_contact"].subaction_of,
        svc.actions["create_contact"].subaction_of
    );
}
