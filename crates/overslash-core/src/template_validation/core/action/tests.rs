//! Tests for [`super::check_action`] and [`super::check_platform_action`].
//! Split out of `mod.rs` for the same reason as `openapi::compile`: the
//! checks are short and the cases against them are not.

use crate::template_validation::core::tests::{minimal_mcp, minimal_valid, param, run};
use crate::types::{McpAuth, Risk, Runtime, ServiceAction, ServiceDefinition};
use std::collections::HashMap;

#[test]
fn unknown_http_method() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().method = "SNOOZE".into();
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "invalid_http_method"));
}

#[test]
fn unknown_path_param() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().path = "/items/{id}".into();
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "unknown_path_param"));
}

#[test]
fn path_param_not_required() {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.path = "/items/{id}".into();
    a.params.insert("id".into(), param("string", false));
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "path_param_not_required"));
}

#[test]
fn invalid_param_type() {
    let mut d = minimal_valid();
    d.actions
        .get_mut("list")
        .unwrap()
        .params
        .insert("x".into(), param("float", false));
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "invalid_param_type"));
}

#[test]
fn invalid_enum_values_empty() {
    let mut d = minimal_valid();
    let mut p = param("string", false);
    p.enum_values = Some(vec![]);
    d.actions
        .get_mut("list")
        .unwrap()
        .params
        .insert("x".into(), p);
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "invalid_enum_values"));
}

#[test]
fn invalid_enum_default_not_member() {
    let mut d = minimal_valid();
    let mut p = param("string", false);
    p.enum_values = Some(vec!["a".into(), "b".into()]);
    p.default = Some(serde_json::json!("c"));
    d.actions
        .get_mut("list")
        .unwrap()
        .params
        .insert("x".into(), p);
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "invalid_enum_values"));
}

#[test]
fn description_unbalanced_brackets() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().description = "List [unclosed".into();
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "unbalanced_brackets"));
}

#[test]
fn description_unknown_param() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().description = "List {ghost}".into();
    let r = run(&d);
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "unknown_description_param")
    );
}

#[test]
fn description_placeholder_defined_ok() {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.description = "List[ filtered by {filter}]".into();
    a.params.insert("filter".into(), param("string", false));
    assert!(run(&d).valid);
}

/// Prose the agent reads is not a label template. LinkedIn's `create_post`
/// documents that an author URN looks like `urn:li:person:{sub}` — real
/// documentation, not a placeholder. Only the `summary` is interpolated,
/// so only the `summary` is grammar-checked.
#[test]
fn braces_in_description_are_prose_when_a_summary_exists() {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.description = "The author URN is urn:li:person:{sub}.".into();
    a.summary = Some("List items".into());
    assert!(run(&d).valid);
}

/// ...but a bad placeholder in the `summary` still fails, and the issue
/// points at `summary` rather than at `description`.
#[test]
fn summary_unknown_param_is_reported_against_summary() {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.description = "List items".into();
    a.summary = Some("List {ghost}".into());
    let r = run(&d);
    let issue = r
        .errors
        .iter()
        .find(|e| e.code == "unknown_description_param")
        .expect("summary placeholder must still be validated");
    assert!(
        issue.path.ends_with(".summary"),
        "issue should name the summary field, got {:?}",
        issue.path
    );
}

/// An action may author the same text in both fields. The reported field
/// has to come from which field exists, not from comparing their contents
/// — otherwise this case blames `description` and sends the author editing
/// a line that is not the one being validated.
#[test]
fn identical_summary_and_description_still_blames_summary() {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.description = "List {ghost}".into();
    a.summary = Some("List {ghost}".into());
    let r = run(&d);
    let issue = r
        .errors
        .iter()
        .find(|e| e.code == "unknown_description_param")
        .expect("the placeholder must still be caught");
    assert!(
        issue.path.ends_with(".summary"),
        "identical text must still be attributed to the field that is \
         interpolated, got {:?}",
        issue.path
    );
}

/// Presence and syntax are independent: a missing `description` must not
/// buy a malformed `summary` a free pass. Both issues are reported, each
/// against its own field.
#[test]
fn absent_description_does_not_suppress_summary_grammar_checks() {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.description = String::new();
    a.summary = Some("List {ghost}".into());
    let r = run(&d);

    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "missing_field" && e.path.ends_with(".description")),
        "the absent description must still be reported: {:?}",
        r.errors
    );
    let placeholder = r
        .errors
        .iter()
        .find(|e| e.code == "unknown_description_param")
        .expect("an empty description must not skip the summary's grammar");
    assert!(placeholder.path.ends_with(".summary"), "{placeholder:?}");
}

/// The ordinary shape of an MCP tool that declares neither — the MCP spec
/// makes a tool description optional and `tools/list` often omits it. An
/// empty label has no grammar to be wrong about, so dropping the early
/// return must not start reporting anything here.
#[test]
fn absent_description_and_summary_report_nothing_extra() {
    let mut d = minimal_mcp(McpAuth::Bearer {
        secret_name: Some("tok".into()),
    });
    for a in d.actions.values_mut() {
        a.description = String::new();
        a.summary = None;
    }
    let r = run(&d);
    assert!(r.valid, "expected a clean report, got {:?}", r.errors);
}

#[test]
fn description_required() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().description = "".into();
    let r = run(&d);
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "missing_field" && e.path.ends_with(".description"))
    );
}

#[test]
fn unknown_scope_param() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().scope_param = "ghost".into();
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "unknown_scope_param"));
}

/// Each entry in a list is checked on its own, and the message names the
/// offending param rather than the whole list.
#[test]
fn unknown_scope_param_inside_a_list() {
    let mut d = minimal_valid();
    let action = d.actions.get_mut("list").unwrap();
    action
        .params
        .insert("folder".into(), param("string", false));
    action.scope_param = crate::types::ScopeParams::parse_list(["folder", "ghost"]).unwrap();
    let r = run(&d);
    let issues: Vec<_> = r
        .errors
        .iter()
        .filter(|e| e.code == "unknown_scope_param")
        .collect();
    assert_eq!(issues.len(), 1, "only the unknown entry should report");
    assert!(issues[0].message.contains("ghost"), "{:?}", issues[0]);
}

/// The label half names a permission namespace the author invents, not a
/// param — validating it against the schema would reject the shipped
/// `to:recipient` form.
#[test]
fn scope_param_label_need_not_name_a_param() {
    let mut d = minimal_valid();
    let action = d.actions.get_mut("list").unwrap();
    action
        .params
        .insert("folder".into(), param("string", false));
    action.scope_param = crate::types::ScopeParams::parse_list(["folder:recipient"]).unwrap();
    let r = run(&d);
    assert!(!r.errors.iter().any(|e| e.code == "unknown_scope_param"));
}

#[test]
fn invalid_response_type() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().response_type = Some("xml".into());
    let r = run(&d);
    assert!(r.errors.iter().any(|e| e.code == "invalid_response_type"));
}

/// Descriptions run through the same substituter, so the linter accepts
/// there what the runtime resolves.
#[test]
fn description_dotted_placeholder_checks_only_the_head_segment() {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.params.insert("query".into(), param("object", false));
    a.description = "Run SQL on database {query.database}".into();
    let r = run(&d);
    assert!(
        !r.errors
            .iter()
            .any(|e| e.code == "unknown_description_param")
    );
}

#[test]
fn risk_method_mismatch_warning() {
    let mut d = minimal_valid();
    d.actions.get_mut("list").unwrap().risk = Risk::Delete.into();
    let r = run(&d);
    assert!(r.valid); // warning, not error
    assert!(r.warnings.iter().any(|w| w.code == "risk_method_mismatch"));
}

// --- pagination -----------------------------------------------------

fn paged(spec: crate::types::PaginationSpec) -> ServiceDefinition {
    let mut d = minimal_valid();
    let action = d.actions.get_mut("list").unwrap();
    action
        .params
        .insert("limit".into(), param("integer", false));
    action
        .params
        .insert("cursor".into(), param("string", false));
    action.pagination = Some(spec);
    d
}

fn cursor_spec() -> crate::types::PaginationSpec {
    crate::types::PaginationSpec {
        page_size: Some(crate::types::PageSize {
            param: "limit".into(),
            default: Some(50),
            max: Some(200),
        }),
        next: crate::types::NextSpec {
            style: crate::types::NextStyle::Cursor,
            param: Some("cursor".into()),
            from: Some("next_cursor".into()),
        },
        items: Some("items".into()),
        has_more: None,
    }
}

#[test]
fn a_well_formed_pagination_block_validates() {
    let r = run(&paged(cursor_spec()));
    assert!(r.valid, "errors: {:?}", r.errors);
}

/// The failure this check exists for: the declaration reads as a bound and
/// applies none, because the parameter it names is not on the action.
#[test]
fn a_page_size_naming_no_declared_param_is_an_error() {
    let mut spec = cursor_spec();
    spec.page_size.as_mut().unwrap().param = "per_page".into();
    let r = run(&paged(spec));
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "unknown_pagination_param"),
        "{:?}",
        r.errors
    );
}

#[test]
fn a_continuation_naming_no_declared_param_is_an_error() {
    let mut spec = cursor_spec();
    spec.next.param = Some("ghost".into());
    let r = run(&paged(spec));
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "unknown_pagination_param"),
        "{:?}",
        r.errors
    );
}

#[test]
fn a_non_numeric_page_size_is_an_error() {
    let mut spec = cursor_spec();
    spec.page_size.as_mut().unwrap().param = "cursor".into();
    let r = run(&paged(spec));
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "invalid_pagination_param_type"),
        "{:?}",
        r.errors
    );
}

/// An offset advances by arithmetic, so a string parameter cannot carry it.
#[test]
fn an_arithmetic_style_needs_a_numeric_continuation_param() {
    let mut spec = cursor_spec();
    spec.next = crate::types::NextSpec {
        style: crate::types::NextStyle::Offset,
        param: Some("cursor".into()),
        from: None,
    };
    let r = run(&paged(spec));
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "invalid_pagination_param_type"),
        "{:?}",
        r.errors
    );
}

/// A warning, not an error: the action still pages correctly, but the
/// number written in the extension is inert and reads like a promise.
#[test]
fn a_shadowed_page_size_default_warns_without_failing() {
    let mut d = paged(cursor_spec());
    d.actions
        .get_mut("list")
        .unwrap()
        .params
        .get_mut("limit")
        .unwrap()
        .default = Some(serde_json::json!(25));
    let r = run(&d);
    assert!(r.valid, "errors: {:?}", r.errors);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.code == "pagination_default_shadowed"),
        "{:?}",
        r.warnings
    );
}

#[test]
fn a_seeded_default_above_the_declared_max_is_an_error() {
    let mut d = paged(cursor_spec());
    d.actions
        .get_mut("list")
        .unwrap()
        .params
        .get_mut("limit")
        .unwrap()
        .default = Some(serde_json::json!(9_000));
    let r = run(&d);
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "pagination_default_exceeds_max"),
        "{:?}",
        r.errors
    );
}

/// A page ordinal has no universal origin, so the parameter's `default:` is the
/// only place a template says whether it counts from 0 or 1. Without it the
/// gateway stops at page one and calls that the whole collection.
#[test]
fn a_page_style_without_a_declared_origin_is_an_error() {
    let mut d = minimal_valid();
    let action = d.actions.get_mut("list").unwrap();
    action
        .params
        .insert("limit".into(), param("integer", false));
    action.params.insert("page".into(), param("integer", false));
    action.pagination = Some(crate::types::PaginationSpec {
        page_size: Some(crate::types::PageSize {
            param: "limit".into(),
            default: Some(20),
            max: None,
        }),
        next: crate::types::NextSpec {
            style: crate::types::NextStyle::Page,
            param: Some("page".into()),
            from: None,
        },
        items: Some("items".into()),
        has_more: None,
    });
    let r = run(&d);
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "pagination_page_origin_unknown"),
        "{:?}",
        r.errors
    );

    // Declaring it — whichever origin the upstream uses — clears the error.
    d.actions
        .get_mut("list")
        .unwrap()
        .params
        .get_mut("page")
        .unwrap()
        .default = Some(serde_json::json!(0));
    let r = run(&d);
    assert!(r.valid, "errors: {:?}", r.errors);
}

/// Without `items` or `has_more`, an arithmetic style cannot tell the last
/// page from a full one — so it offers a next page that is not there.
#[test]
fn an_arithmetic_style_with_no_end_marker_warns() {
    let mut d = minimal_valid();
    let action = d.actions.get_mut("list").unwrap();
    action
        .params
        .insert("limit".into(), param("integer", false));
    action
        .params
        .insert("offset".into(), param("integer", false));
    action.pagination = Some(crate::types::PaginationSpec {
        page_size: Some(crate::types::PageSize {
            param: "limit".into(),
            default: Some(50),
            max: None,
        }),
        next: crate::types::NextSpec {
            style: crate::types::NextStyle::Offset,
            param: Some("offset".into()),
            from: None,
        },
        items: None,
        has_more: None,
    });
    let r = run(&d);
    assert!(r.valid, "errors: {:?}", r.errors);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.code == "pagination_unbounded_end"),
        "{:?}",
        r.warnings
    );
}

#[test]
fn platform_namespace_action_allowed() {
    // An action with empty method/path (like overslash.yaml) must validate
    // clean as long as description is present.
    let mut d = ServiceDefinition {
        default_timeout_ms: None,
        secrets: Vec::new(),
        config: Vec::new(),
        key: "overslash".into(),
        display_name: "Overslash".into(),
        description: None,
        hosts: vec![],
        category: Some("platform".into()),
        hidden: false,
        icon: None,
        auth: vec![],
        actions: HashMap::new(),
        runtime: Runtime::Platform,
        mcp: None,
        instance_defaults: None,
    };
    d.actions.insert(
        "manage_secrets".into(),
        ServiceAction {
            wait_mode: None,
            handoff_after_ms: None,
            pagination: None,
            timeout_ms: None,
            method: String::new(),
            path: String::new(),
            description: "Manage secrets".into(),
            summary: None,
            risk: Risk::Write.into(),
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
            upload: None,
        },
    );
    let r = run(&d);
    assert!(r.valid, "errors: {:?}", r.errors);
}

#[test]
fn mcp_description_is_optional() {
    // MCP spec: tool description is optional. A tools/list response
    // that omits description should still validate — HTTP actions
    // require one, platform actions require one, but MCP tools do not.
    let mut d = minimal_mcp(McpAuth::None);
    d.actions.get_mut("search").unwrap().description = String::new();
    let r = run(&d);
    assert!(r.valid, "errors: {:?}", r.errors);
}

#[test]
fn http_description_still_required() {
    // Regression guard: making description optional for MCP must not
    // relax the HTTP path. Platform + HTTP actions still reject empty
    // descriptions.
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.description = String::new();
    let r = run(&d);
    assert!(
        r.errors
            .iter()
            .any(|e| e.code == "missing_field" && e.path.contains("description"))
    );
}
