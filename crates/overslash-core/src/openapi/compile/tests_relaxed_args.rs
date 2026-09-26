//! Compile-time tests for `x-overslash-additional-properties`: the `info` →
//! operation fold, the platform-action exclusion, and the fail-closed
//! behaviour on a malformed value.
//!
//! A sibling of [`super::tests`] rather than a section inside it, for the
//! reason that file's own header gives: the gate that caps a source file at a
//! thousand lines does not distinguish test code from the rest, and `tests.rs`
//! is already at the line.

use super::*;
use crate::openapi::normalize_aliases;
use serde_json::json;
/// The `info` rung folds onto every action at compile time, and an operation
/// overrides it in *both* directions. Unlike the timeout cascade above, this
/// one is resolved here rather than at call time: there is no per-call or
/// per-org rung to leave room for, so the action field is the single answer
/// the runtime reads.
#[test]
fn additional_properties_folds_from_info_and_the_operation_overrides_it() {
    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Wide", "key": "wide", "additional-properties": true
        },
        "servers": [{"url": "https://wide.example"}],
        "paths": {
            "/loose": {"get": {
                "operationId": "loose", "description": "inherits",
                "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]
            }},
            "/tight": {"get": {
                "operationId": "tight", "description": "re-tightened",
                "additional-properties": false,
                "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]
            }}
        }
    });
    normalize_aliases(&mut doc);
    let (svc, warnings) = compile_service(&doc).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(svc.default_additional_properties);
    assert!(svc.actions["loose"].additional_properties);
    // The falsy nearer value wins, the same way an operation's own `security`
    // beats the root's even when it is an explicit opt-out.
    assert!(!svc.actions["tight"].additional_properties);
}

#[test]
fn additional_properties_defaults_to_strict_and_is_elided_on_the_wire() {
    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {"title": "Plain", "key": "plain"},
        "servers": [{"url": "https://plain.example"}],
        "paths": {"/a": {"get": {"operationId": "a", "description": "d"}}}
    });
    normalize_aliases(&mut doc);
    let (svc, _) = compile_service(&doc).unwrap();
    assert!(!svc.default_additional_properties);
    assert!(!svc.actions["a"].additional_properties);
    // Every persisted row and shipped fixture predates the field, so it must
    // not appear when unset or the round-trip changes shape.
    let wire = serde_json::to_value(&svc).unwrap();
    assert!(wire.get("default_additional_properties").is_none());
    assert!(wire["actions"]["a"].get("additional_properties").is_none());
}

/// A platform action is answered in this process against a param set we own,
/// so relaxing the gate there would accept an argument the handler then drops.
/// The `info` default must not reach one.
#[test]
fn additional_properties_never_folds_onto_a_platform_action() {
    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Kernel", "key": "kernel", "additional-properties": true
        },
        "runtime": "platform",
        "paths": {},
        "platform_actions": {
            "list_things": {"description": "list", "risk": "read"}
        }
    });
    normalize_aliases(&mut doc);
    let (svc, _) = compile_service(&doc).unwrap();
    assert!(
        svc.default_additional_properties,
        "the info rung is still read"
    );
    assert!(
        !svc.actions["list_things"].additional_properties,
        "a platform action must stay strict",
    );
}

#[test]
fn additional_properties_warns_and_stays_strict_when_malformed_at_info() {
    // Fails closed: a quoting mistake must not be able to grant the
    // relaxation, and must not take the whole service down either.
    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {"title": "Oops", "key": "oops", "additional-properties": "true"},
        "servers": [{"url": "https://oops.example"}],
        "paths": {"/a": {"get": {"operationId": "a", "description": "d"}}}
    });
    normalize_aliases(&mut doc);
    let (svc, warnings) = compile_service(&doc).unwrap();
    assert!(!svc.default_additional_properties);
    assert!(!svc.actions["a"].additional_properties);
    assert!(
        warnings.iter().any(|w| w.code == "openapi_invalid"),
        "expected a warning, got {warnings:?}",
    );
}
