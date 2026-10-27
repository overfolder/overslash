use std::collections::HashMap;

use serde_json::{Map, Value, json};

use super::*;
use crate::types::{Risk, Subaction, SubactionSpec};

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn variant(key: &str, verb: Option<&str>, phrase: Option<&str>) -> Subaction {
    Subaction {
        key: key.into(),
        matches: "true".into(),
        description: format!("{key} description"),
        verb: verb.map(Into::into),
        phrase: phrase.map(Into::into),
        summary: None,
        vars: Default::default(),
        risk: Risk::Write,
        scope_param: Default::default(),
        disclose: vec![],
        redact: vec![],
        timeout_ms: None,
        required_scopes: vec![],
        transform: None,
        params: HashMap::new(),
    }
}

fn hubspot_spec() -> SubactionSpec {
    SubactionSpec {
        each: None,
        summary: None,
        verb: None,
        phrase: None,
        variants: vec![
            variant(
                "create_contact",
                Some("create"),
                Some("contact {item.label}"),
            ),
            variant("create_deal", Some("create"), Some("deal {item.label}")),
            variant("update_deal", Some("update"), Some("deal {item.label}")),
        ],
    }
}

fn item(variant: Option<usize>, v: Value) -> ClassifiedItem {
    ClassifiedItem {
        variant,
        item: v.as_object().cloned().unwrap_or_default(),
    }
}

fn none() -> (HashMap<String, Value>, HashMap<String, String>) {
    (HashMap::new(), HashMap::new())
}

#[test]
fn english_list_joins_like_a_sentence() {
    assert_eq!(english_list(&[]), "");
    assert_eq!(english_list(&s(&["A"])), "A");
    assert_eq!(english_list(&s(&["A", "B"])), "A and B");
    assert_eq!(english_list(&s(&["A", "B", "C"])), "A, B and C");
    assert_eq!(
        english_list(&s(&["1", "2", "3", "4", "5", "6", "7"])),
        "1, 2, 3, 4, 5 and 2 more"
    );
}

#[test]
fn enumerations_are_found_by_paren_depth() {
    let t = "Create {enumerate(contact {item.label} (x))} now";
    let found = find_enumerations(t).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, "contact {item.label} (x)");
    assert_eq!(
        &t[found[0].0.clone()],
        "{enumerate(contact {item.label} (x))}"
    );
    assert!(find_enumerations("Create {enumerate(contact").is_err());
}

#[test]
fn default_composition_groups_by_verb() {
    let (p, r) = none();
    let items = vec![
        item(Some(0), json!({"label": "jane@acme.com"})),
        item(Some(1), json!({"label": "Acme renewal"})),
        item(Some(2), json!({"label": "Big Co"})),
    ];
    assert_eq!(
        describe_call(
            &hubspot_spec(),
            &items,
            "Create or update CRM records",
            &p,
            &r
        ),
        "Create contact jane@acme.com and deal Acme renewal; update deal Big Co"
    );
}

#[test]
fn a_variant_summary_wins_when_every_item_is_that_variant() {
    let (p, r) = none();
    let mut spec = hubspot_spec();
    spec.variants[0].summary = Some("Create {count} contacts: {enumerate({item.label})}".into());
    let items = vec![
        item(Some(0), json!({"label": "a@x.com"})),
        item(Some(0), json!({"label": "b@x.com"})),
    ];
    assert_eq!(
        describe_call(&spec, &items, "parent", &p, &r),
        "Create 2 contacts: a@x.com and b@x.com"
    );
    // A mixed call falls through to the default composition.
    let mixed = vec![items[0].clone(), item(Some(2), json!({"label": "Big Co"}))];
    assert_eq!(
        describe_call(&spec, &mixed, "parent", &p, &r),
        "Create contact a@x.com; update deal Big Co"
    );
}

#[test]
fn a_call_summary_sees_verb_phrase_and_subaction() {
    let (p, r) = none();
    let mut spec = hubspot_spec();
    spec.summary = Some("{enumerate({item.verb} {item.phrase})}".into());
    let items = vec![
        item(Some(0), json!({"label": "jane@acme.com"})),
        item(Some(2), json!({"label": "Big Co"})),
    ];
    assert_eq!(
        describe_call(&spec, &items, "parent", &p, &r),
        "create contact jane@acme.com and update deal Big Co"
    );
}

#[test]
fn unclaimed_items_keep_the_parent_label() {
    let (p, r) = none();
    let items = vec![
        item(Some(0), json!({"label": "jane@acme.com"})),
        item(None, json!({"objectType": "notes"})),
        item(None, json!({"objectType": "notes"})),
    ];
    assert_eq!(
        describe_call(
            &hubspot_spec(),
            &items,
            "Create or update CRM records",
            &p,
            &r
        ),
        "Create contact jane@acme.com; Create or update CRM records"
    );
}

#[test]
fn a_bare_item_placeholder_resolves_for_a_single_item() {
    let (p, r) = none();
    let mut spec = hubspot_spec();
    spec.variants[0].summary = Some("Create contact {item.label}".into());
    let one = vec![item(Some(0), json!({"label": "jane@acme.com"}))];
    assert_eq!(
        describe_call(&spec, &one, "parent", &p, &r),
        "Create contact jane@acme.com"
    );
}

/// Caller data carrying grammar characters is printed, never re-read: the
/// rendered list is parked behind a marker while the outer template runs.
#[test]
fn rendered_lists_are_not_reinterpolated() {
    let (mut p, r) = none();
    p.insert("secret".into(), json!("leak"));
    let items = [item(Some(0), json!({"label": "[{secret}]"}))];
    let out = render_group(
        "Create {enumerate(contact {item.label})}",
        &items.iter().map(|i| &i.item).collect::<Vec<_>>(),
        &p,
        &r,
    );
    assert_eq!(out, "Create contact [{secret}]");
}

#[test]
fn item_placeholders_reach_nested_fields() {
    let (p, r) = none();
    let it: Map<String, Value> = json!({"properties": {"email": "jane@acme.com"}})
        .as_object()
        .cloned()
        .unwrap();
    assert_eq!(
        render_item("contact {item.properties.email}", &it, &p, &r),
        "contact jane@acme.com"
    );
}

#[test]
fn classifier_output_merges_vars_and_checks_indices() {
    let spec = hubspot_spec();
    let out = json!([
        {"item": {"objectType": "contacts"}, "sub": 0, "vars": {"label": "x"}},
        {"item": 7, "sub": null, "vars": {}}
    ]);
    let items = parse_classifier_output(&spec, &out).unwrap();
    assert_eq!(items[0].variant, Some(0));
    assert_eq!(items[0].item["label"], json!("x"));
    assert_eq!(items[1].variant, None);
    assert_eq!(items[1].item["value"], json!(7));
    assert!(parse_classifier_output(&spec, &json!([{"item": {}, "sub": 9}])).is_err());
    assert!(parse_classifier_output(&spec, &json!({})).is_err());
}

#[test]
fn classifier_program_wraps_every_expression() {
    let mut spec = hubspot_spec();
    spec.each = Some(".a[]".into());
    spec.variants[1]
        .vars
        .insert("label".into(), ".properties.dealname".into());
    let prog = spec.classifier_program();
    assert!(prog.starts_with("def __ovs_m(f): [f] | any;"));
    assert!(prog.contains("[.a[]] | map("));
    assert!(prog.contains("if __ovs_m(true) then 0 elif __ovs_m(true) then 1"));
    assert!(prog.contains("if $s == 1 then {\"label\": ([.properties.dealname] | first)}"));
}

#[test]
fn malformed_classifier_entries_are_tolerated_or_refused() {
    let spec = hubspot_spec();
    let items = parse_classifier_output(&spec, &json!([{"sub": 1}])).unwrap();
    assert_eq!(items[0].variant, Some(1));
    assert!(
        items[0].item.is_empty(),
        "an entry without `item` is an empty item"
    );
    assert!(
        parse_classifier_output(&spec, &json!([{"item": {}, "sub": "0"}])).is_err(),
        "`sub` must be an index"
    );
}

#[test]
fn an_enumerate_not_closed_by_a_brace_is_unclosed() {
    assert!(find_enumerations("Create {enumerate(contact) now").is_err());
    let (p, r) = none();
    // At runtime the lint's error degrades to plain interpolation.
    assert_eq!(
        render_group("Create {enumerate(contact", &[], &p, &r),
        "Create {enumerate(contact"
    );
}

#[test]
fn a_variant_without_verb_and_phrase_contributes_its_label_once() {
    let (p, r) = none();
    let mut spec = hubspot_spec();
    spec.variants.push(variant("archive_note", None, None));
    spec.variants
        .push(variant("purge_thing", Some("purge"), None));
    spec.variants[4].summary = Some("Purge {count} things".into());
    let items = vec![
        item(Some(3), json!({})),
        item(Some(0), json!({"label": "jane@acme.com"})),
        item(Some(3), json!({})),
        item(Some(4), json!({})),
        item(Some(4), json!({})),
    ];
    assert_eq!(
        describe_call(&spec, &items, "parent", &p, &r),
        "archive_note description; create contact jane@acme.com; Purge 2 things",
        "a verb without a phrase is not composable, the summary renders over its group, \
         and only the first clause is capitalized"
    );
}

#[test]
fn a_parent_verb_and_phrase_compose_unclaimed_items() {
    let (p, r) = none();
    let mut spec = hubspot_spec();
    spec.verb = Some("touch".into());
    spec.phrase = Some("{item.objectType}".into());
    let items = vec![
        item(None, json!({"objectType": "notes"})),
        item(Some(0), json!({"label": "jane@acme.com"})),
        item(None, json!({"objectType": "tasks"})),
    ];
    assert_eq!(
        describe_call(&spec, &items, "parent", &p, &r),
        "Touch notes and tasks; create contact jane@acme.com"
    );
}

#[test]
fn no_items_describe_as_the_parent() {
    let (p, r) = none();
    assert_eq!(
        describe_call(&hubspot_spec(), &[], "Create or update CRM records", &p, &r),
        "Create or update CRM records"
    );
}

#[test]
fn a_call_summary_marks_unclaimed_and_unphrased_items() {
    let (p, r) = none();
    let mut spec = hubspot_spec();
    spec.variants.push(variant("archive_note", None, None));
    spec.summary = Some("{enumerate(<[{item.subaction}][ {item.verb}]>)}".into());
    let items = vec![
        item(Some(3), json!({})),
        item(None, json!({})),
        item(Some(0), json!({"label": "a@x.com"})),
    ];
    assert_eq!(
        describe_call(&spec, &items, "parent", &p, &r),
        "<archive_note>, <> and <create_contact create>",
        "an item without a verb renders none; an unclaimed one has a null subaction"
    );
}

#[test]
fn item_params_flatten_the_item() {
    let it = item(Some(0), json!({"objectType": "contacts", "n": 1}));
    let p = item_params(&it.item);
    assert_eq!(p.len(), 2);
    assert_eq!(p["objectType"], json!("contacts"));
}

#[test]
fn the_spec_finds_variants_and_builds_with_none() {
    let spec = hubspot_spec();
    assert_eq!(spec.variant("update_deal").unwrap().key, "update_deal");
    assert!(spec.variant("nope").is_none());

    let empty = SubactionSpec::default();
    let prog = empty.classifier_program();
    assert!(prog.contains("(null)"), "{prog}");
    assert!(prog.contains("({})"), "{prog}");
}
