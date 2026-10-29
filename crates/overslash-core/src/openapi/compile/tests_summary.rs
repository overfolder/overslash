//! Compile-time tests for `info.summary`, the one-line catalog tagline: how it
//! is read, and the single-line / length warnings.
//!
//! A sibling of [`super::tests`] for the line-cap reason `tests_relaxed_args`
//! gives.

use super::*;
use crate::openapi::{lint_extensions, normalize_aliases};
use serde_json::json;

fn compile_info(info: Value) -> (ServiceDefinition, Vec<ValidationIssue>) {
    let mut doc = json!({"openapi": "3.1.0", "info": info, "paths": {}});
    assert!(normalize_aliases(&mut doc).is_empty());
    compile_service(&doc).unwrap()
}

fn summary_warnings(warnings: &[ValidationIssue]) -> Vec<&ValidationIssue> {
    warnings
        .iter()
        .filter(|w| w.path == "info.summary")
        .collect()
}

#[test]
fn summary_is_read_from_info_and_trimmed() {
    let (svc, warnings) = compile_info(json!({
        "title": "GitHub", "key": "github",
        "summary": "  Repositories, issues, and pull requests  ",
        "description": "A long agent-facing paragraph.",
    }));
    assert_eq!(
        svc.summary.as_deref(),
        Some("Repositories, issues, and pull requests")
    );
    assert_eq!(
        svc.description.as_deref(),
        Some("A long agent-facing paragraph.")
    );
    assert!(summary_warnings(&warnings).is_empty(), "{warnings:?}");
}

#[test]
fn absent_or_blank_summary_is_none_without_a_warning() {
    for info in [
        json!({"title": "T", "key": "t"}),
        json!({"title": "T", "key": "t", "summary": "   "}),
    ] {
        let (svc, warnings) = compile_info(info);
        assert_eq!(svc.summary, None);
        assert!(summary_warnings(&warnings).is_empty(), "{warnings:?}");
    }
}

#[test]
fn multi_line_summary_warns_and_is_kept() {
    let (svc, warnings) = compile_info(json!({
        "title": "T", "key": "t", "summary": "First line\nsecond line",
    }));
    assert_eq!(svc.summary.as_deref(), Some("First line\nsecond line"));
    let w = summary_warnings(&warnings);
    assert_eq!(w.len(), 1, "{warnings:?}");
    assert_eq!(w[0].code, "openapi_invalid");
    assert!(w[0].message.contains("single line"), "{}", w[0].message);
}

/// Counted in chars, not bytes: 80 multi-byte chars is within the cap even
/// though it is 160 bytes.
#[test]
fn summary_length_cap_counts_chars() {
    let at_cap = "é".repeat(SUMMARY_MAX_CHARS);
    let (_, warnings) = compile_info(json!({"title": "T", "key": "t", "summary": at_cap}));
    assert!(summary_warnings(&warnings).is_empty(), "{warnings:?}");

    let over = "é".repeat(SUMMARY_MAX_CHARS + 1);
    let (svc, warnings) = compile_info(json!({"title": "T", "key": "t", "summary": over}));
    assert_eq!(svc.summary.as_deref(), Some(over.as_str()));
    let w = summary_warnings(&warnings);
    assert_eq!(w.len(), 1, "{warnings:?}");
    assert!(w[0].message.contains("at most 80"), "{}", w[0].message);
}

#[test]
fn non_string_summary_warns_and_is_dropped() {
    let (svc, warnings) = compile_info(json!({"title": "T", "key": "t", "summary": 42}));
    assert_eq!(svc.summary, None);
    assert_eq!(summary_warnings(&warnings).len(), 1, "{warnings:?}");
}

/// `summary` is the standard OpenAPI key, so it is lint-clean; a misspelling is
/// not.
#[test]
fn summary_is_lint_clean_and_a_typo_is_flagged() {
    let doc = json!({"openapi": "3.1.0", "info": {"title": "T", "summary": "Short"}, "paths": {}});
    assert!(lint_extensions(&doc).is_empty());

    let doc = json!({"openapi": "3.1.0", "info": {"title": "T", "sumary": "Short"}, "paths": {}});
    let issues = lint_extensions(&doc);
    assert!(
        issues
            .iter()
            .any(|i| i.path == "info.sumary" && i.code == "unknown_template_key"),
        "{issues:?}"
    );
}
