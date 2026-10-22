//! Compile-time tests for `x-overslash-success`: the `info` → operation fold,
//! the HTTP-only reach, and how a malformed value is reported.
//!
//! A sibling of [`super::tests`] for the line-cap reason `tests_relaxed_args`
//! gives.

use super::*;
use crate::openapi::normalize_aliases;
use serde_json::json;

fn compile(mut doc: Value) -> (ServiceDefinition, Vec<ValidationIssue>) {
    normalize_aliases(&mut doc);
    compile_service(&doc).unwrap()
}

#[test]
fn success_folds_from_info_and_the_operation_overrides_it() {
    let (svc, warnings) = compile(json!({
        "openapi": "3.1.0",
        "info": {"title": "Chat", "key": "chat", "success": ".ok == true"},
        "servers": [{"url": "https://chat.example"}],
        "paths": {
            "/a": {"get": {"operationId": "inherits", "description": "d"}},
            "/b": {"get": {
                "operationId": "overrides", "description": "d",
                "success": ".status == \"done\""
            }}
        }
    }));
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        svc.actions["inherits"].success.as_deref(),
        Some(".ok == true")
    );
    assert_eq!(
        svc.actions["overrides"].success.as_deref(),
        Some(".status == \"done\"")
    );
}

#[test]
fn success_is_absent_and_elided_when_undeclared() {
    let (svc, _) = compile(json!({
        "openapi": "3.1.0",
        "info": {"title": "Plain", "key": "plain"},
        "servers": [{"url": "https://plain.example"}],
        "paths": {"/a": {"get": {"operationId": "a", "description": "d"}}}
    }));
    assert!(svc.actions["a"].success.is_none());
    let wire = serde_json::to_value(&svc).unwrap();
    assert!(wire["actions"]["a"].get("success").is_none());
}

/// A platform action answers from this process, so there is no upstream body
/// for the `info` default to judge.
#[test]
fn success_never_folds_onto_a_platform_action() {
    let (svc, _) = compile(json!({
        "openapi": "3.1.0",
        "info": {"title": "Kernel", "key": "kernel", "success": ".ok"},
        "runtime": "platform",
        "paths": {},
        "platform_actions": {
            "list_things": {"description": "list", "risk": "read"}
        }
    }));
    assert!(svc.actions["list_things"].success.is_none());
}

#[test]
fn a_malformed_success_warns_at_info_and_errors_on_an_operation() {
    let (svc, warnings) = compile(json!({
        "openapi": "3.1.0",
        "info": {"title": "W", "key": "w", "success": true},
        "servers": [{"url": "https://w.example"}],
        "paths": {"/a": {"get": {"operationId": "a", "description": "d"}}}
    }));
    assert!(svc.actions["a"].success.is_none());
    assert!(
        warnings
            .iter()
            .any(|w| w.path == "info.x-overslash-success"),
        "{warnings:?}"
    );

    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {"title": "E", "key": "e"},
        "servers": [{"url": "https://e.example"}],
        "paths": {"/a": {"get": {
            "operationId": "a", "description": "d", "success": ""
        }}}
    });
    normalize_aliases(&mut doc);
    let errors = compile_service(&doc).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.path == "paths./a.get.x-overslash-success"),
        "{errors:?}"
    );
}
