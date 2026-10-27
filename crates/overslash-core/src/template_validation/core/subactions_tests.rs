//! Tests for [`super::check_subactions`]: the label grammar per kind, and the
//! warnings for shapes that parse but misbehave.

use crate::template_validation::ValidationReport;
use crate::template_validation::core::tests::{minimal_valid, param, run};
use crate::types::SubactionSpec;
use serde_json::{Value, json};

/// Validate `minimal_valid` with `block` as the `list` action's subactions.
fn check(block: Value) -> ValidationReport {
    let mut d = minimal_valid();
    let a = d.actions.get_mut("list").unwrap();
    a.params.insert("portal".into(), param("string", false));
    a.subactions = Some(serde_json::from_value::<SubactionSpec>(block).unwrap());
    run(&d)
}

fn variant(extra: Value) -> Value {
    let mut v =
        json!({"key": "create_contact", "match": "true", "description": "", "risk": "write"});
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

fn codes(issues: &[crate::template_validation::ValidationIssue]) -> Vec<(&str, &str)> {
    issues
        .iter()
        .map(|i| (i.code.as_str(), i.path.as_str()))
        .collect()
}

#[test]
fn a_well_formed_block_is_clean() {
    let r = check(json!({
        "each": ".objects[]",
        "summary": "Write {count} records in {portal}: {enumerate({item.verb} {item.phrase})}",
        "verb": "touch",
        "phrase": "record[ {item.label}]",
        "variants": [variant(json!({
            "match": ".objectType == \"contacts\"",
            "verb": "create",
            "phrase": "contact '{item.label}'[ in {portal}]",
            "summary": "Create {count} contacts: {enumerate('{item.label}')}"
        }))]
    }));
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn a_phrase_may_not_enumerate_or_count() {
    let r = check(json!({"variants": [variant(json!({
        "verb": "create",
        "phrase": "{count} contacts {enumerate({item.label})}"
    }))]}));
    let errs = codes(&r.errors);
    let path = "actions.list.subactions.create_contact.phrase";
    assert!(
        errs.contains(&("invalid_description_syntax", path)),
        "{errs:?}"
    );
    assert!(
        errs.contains(&("unknown_description_param", path)),
        "`count` is a group placeholder: {errs:?}"
    );
}

#[test]
fn count_is_only_a_group_placeholder_outside_the_loop() {
    // Inside an `enumerate` body the text is per item again, so `{count}`
    // there is unknown even in a summary.
    let r = check(
        json!({"summary": "{count}: {enumerate({item.label} of {count})}", "variants": [variant(json!({}))]}),
    );
    let msgs: Vec<_> = r
        .errors
        .iter()
        .filter(|e| e.code == "unknown_description_param")
        .collect();
    assert_eq!(msgs.len(), 1, "{:?}", r.errors);
    assert_eq!(msgs[0].path, "actions.list.subactions.summary");
    assert!(
        !msgs[0].message.contains("`count`"),
        "the per-item message must not offer `count`: {}",
        msgs[0].message
    );
}

#[test]
fn an_unknown_placeholder_names_what_is_allowed() {
    let r = check(json!({"variants": [variant(json!({"summary": "Create {nope}"}))]}));
    let e = r
        .errors
        .iter()
        .find(|e| e.code == "unknown_description_param")
        .expect("unknown param reported");
    assert_eq!(e.path, "actions.list.subactions.create_contact.summary");
    assert!(
        e.message.contains("{nope}") && e.message.contains("`count`"),
        "{}",
        e.message
    );
}

#[test]
fn an_unclosed_enumerate_stops_the_label_check() {
    let r = check(
        json!({"summary": "Write {enumerate({item.label} {bogus}", "variants": [variant(json!({}))]}),
    );
    let errs = codes(&r.errors);
    assert_eq!(
        errs,
        vec![(
            "invalid_description_syntax",
            "actions.list.subactions.summary"
        )],
        "one syntax error, no follow-on placeholder noise"
    );
    assert!(r.errors[0].message.contains("unclosed `{enumerate(`"));
}

#[test]
fn brackets_and_braces_are_checked_in_and_out_of_loops() {
    let r = check(json!({
        "summary": "Write [a [b]] {enumerate({item.label)}",
        "phrase": "record [{item.label}",
        "verb": "touch",
        "variants": [variant(json!({}))]
    }));
    let errs = codes(&r.errors);
    assert!(
        errs.contains(&("unbalanced_brackets", "actions.list.subactions.summary")),
        "{errs:?}"
    );
    assert!(
        errs.contains(&(
            "invalid_description_syntax",
            "actions.list.subactions.summary"
        )),
        "unclosed `{{` in the loop body: {errs:?}"
    );
    assert!(
        errs.contains(&("unbalanced_brackets", "actions.list.subactions.phrase")),
        "{errs:?}"
    );
}

#[test]
fn verb_and_phrase_must_come_together() {
    let r = check(json!({
        "verb": "touch",
        "variants": [
            variant(json!({"phrase": "contact"})),
            variant(json!({"key": "paired", "verb": "create", "phrase": "deal"})),
        ]
    }));
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let warns = codes(&r.warnings);
    assert_eq!(
        warns,
        vec![
            ("subactions_verb_without_phrase", "actions.list.subactions"),
            (
                "subactions_verb_without_phrase",
                "actions.list.subactions.create_contact"
            ),
        ]
    );
}

#[test]
fn an_array_match_without_each_warns() {
    let block = |each: Option<&str>| {
        let mut b = json!({"variants": [variant(json!({"match": ".objects[] | .objectType == \"contacts\""}))]});
        if let Some(e) = each {
            b["each"] = json!(e);
        }
        b
    };
    let warns = check(block(None)).warnings;
    assert_eq!(
        codes(&warns),
        vec![(
            "subactions_match_without_each",
            "actions.list.subactions.create_contact.match"
        )]
    );
    assert!(check(block(Some(".objects[]"))).warnings.is_empty());
}

#[test]
fn platform_actions_skip_the_check() {
    let mut d = minimal_valid();
    d.runtime = crate::types::Runtime::Platform;
    d.actions.get_mut("list").unwrap().subactions = Some(
        serde_json::from_value(json!({"summary": "{nope", "variants": [variant(json!({}))]}))
            .unwrap(),
    );
    assert!(
        !run(&d).errors.iter().any(|e| e.path.contains("subactions")),
        "platform templates are not template-authored"
    );
}
