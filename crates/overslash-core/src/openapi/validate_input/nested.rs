//! Validating a supplied value against a parameter's declared
//! [`ParamShape`].
//!
//! The nested twin of [`validate_args`](super::validate_args), and deliberately
//! the *same three checks*: a required property must be present, an undeclared
//! key is rejected, and a declared string `enum` must be respected. Type
//! rejection stays out of scope at every depth for the reason the parent module
//! gives — hand-written schemas under-specify types, and rejecting a value
//! because its JSON type differs from the declared one produces false 400s on
//! calls the upstream would have accepted.
//!
//! Two consequences of that follow, and both are intentional:
//!
//! - A value whose *kind* does not match the shape (an object where an array is
//!   declared) is not an error and is simply not descended into. The shape
//!   describes a structure; it does not assert one.
//! - A parameter whose template authored no sub-schema is unconstrained, exactly
//!   as every parameter was before shapes existed. Silence here means "not
//!   described", never "described as empty".

use serde_json::Value;

use crate::types::{NestedParam, ParamShape};

use super::error::{ArgError, closest_match, value_to_plain_string};

/// How many elements of an array are validated.
///
/// Validation is a floor that lets an agent self-correct, not a gate the
/// upstream depends on — so a 10 000-row bulk write is checked at its head and
/// then handed on, rather than costing a linear walk (and a potential 10 000
/// error messages) on the request path. Elements past the cap still reach the
/// upstream, which is the layer that is authoritative about them anyway.
const MAX_VALIDATED_ELEMENTS: usize = 100;

/// Check `value` against `shape`, appending one [`ArgError`] per problem.
///
/// `path` is the caller-facing address of `value` — the parameter name at the
/// top, then `parent.child` and `parent[3]` as the walk descends — so an error
/// names the field an agent has to fix rather than the parameter it lives
/// under.
///
/// `relaxed` is the action's `x-overslash-additional-properties`. It **spreads
/// inward and never back out**: a sub-schema may add `additionalProperties:
/// true` to open itself further, but cannot re-close a level its action opened.
/// The two spellings are not symmetrical inputs — `additionalProperties` is
/// absent far more often than it is deliberately `false`, so honouring a
/// re-tightening would mostly be honouring an omission.
pub(super) fn validate_nested(
    shape: &ParamShape,
    value: &Value,
    relaxed: bool,
    path: &str,
    errors: &mut Vec<ArgError>,
) {
    match shape {
        ParamShape::Object {
            properties,
            additional_properties,
        } => {
            let Some(map) = value.as_object() else { return };
            let relaxed = relaxed || *additional_properties;

            for (name, declared) in properties {
                let at = format!("{path}.{name}");
                match map.get(name) {
                    Some(v) if !v.is_null() => check_value(declared, v, relaxed, &at, errors),
                    _ if declared.required => errors.push(ArgError::Missing { field: at }),
                    _ => {}
                }
            }

            if !relaxed {
                let mut expected: Vec<String> = properties.keys().cloned().collect();
                expected.sort();
                for name in map.keys() {
                    if !properties.contains_key(name) {
                        errors.push(ArgError::Unknown {
                            field: format!("{path}.{name}"),
                            suggestion: closest_match(name, properties.keys().map(String::as_str)),
                            expected: expected.clone(),
                        });
                    }
                }
            }
        }
        ParamShape::Array { items } => {
            let Some(arr) = value.as_array() else { return };
            for (i, element) in arr.iter().take(MAX_VALIDATED_ELEMENTS).enumerate() {
                if element.is_null() {
                    continue;
                }
                check_value(items, element, relaxed, &format!("{path}[{i}]"), errors);
            }
        }
    }
}

/// Check one declared property's value: its own `enum`, then its own shape.
fn check_value(
    declared: &NestedParam,
    value: &Value,
    relaxed: bool,
    path: &str,
    errors: &mut Vec<ArgError>,
) {
    // An empty member list is not a constraint: members are collected via
    // `as_str`, so a numeric enum lowers to `Some(vec![])`. Same reading the
    // top level gives it.
    if !relaxed
        && let Some(allowed) = declared.enum_values.as_ref().filter(|a| !a.is_empty())
        && !value
            .as_str()
            .is_some_and(|s| allowed.contains(&s.to_string()))
    {
        errors.push(ArgError::NotInEnum {
            field: path.to_string(),
            value: value_to_plain_string(value),
            allowed: allowed.clone(),
        });
    }
    if let Some(inner) = declared.shape.as_deref() {
        validate_nested(inner, value, relaxed, path, errors);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    fn prop(param_type: &str, required: bool) -> NestedParam {
        NestedParam {
            param_type: param_type.into(),
            required,
            ..Default::default()
        }
    }

    fn object(props: &[(&str, NestedParam)]) -> ParamShape {
        ParamShape::Object {
            properties: props
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
            additional_properties: false,
        }
    }

    fn run(shape: &ParamShape, value: Value, relaxed: bool) -> Vec<ArgError> {
        let mut errors = Vec::new();
        validate_nested(shape, &value, relaxed, "createRequest", &mut errors);
        errors
    }

    #[test]
    fn a_missing_nested_required_field_names_its_full_path() {
        let shape = object(&[("objectType", prop("string", true))]);
        let errors = run(&shape, json!({}), false);
        assert_eq!(
            errors,
            vec![ArgError::Missing {
                field: "createRequest.objectType".into()
            }]
        );
        assert!(
            errors[0].message().contains("createRequest.objectType"),
            "the message must name the field an agent has to fix"
        );
    }

    #[test]
    fn an_undeclared_nested_key_is_rejected_with_a_suggestion() {
        let shape = object(&[("objectType", prop("string", false))]);
        let errors = run(&shape, json!({ "objectTypes": "contacts" }), false);
        assert_eq!(
            errors,
            vec![ArgError::Unknown {
                field: "createRequest.objectTypes".into(),
                suggestion: Some("objectType".into()),
                expected: vec!["objectType".into()],
            }]
        );
    }

    #[test]
    fn a_nested_enum_is_enforced() {
        let shape = object(&[(
            "objectType",
            NestedParam {
                param_type: "string".into(),
                enum_values: Some(vec!["contacts".into(), "deals".into()]),
                ..Default::default()
            },
        )]);
        assert!(run(&shape, json!({ "objectType": "contacts" }), false).is_empty());
        assert_eq!(
            run(&shape, json!({ "objectType": "tickets" }), false).len(),
            1
        );
    }

    #[test]
    fn an_array_reports_the_offending_index() {
        let shape = ParamShape::Array {
            items: Box::new(NestedParam {
                param_type: "object".into(),
                shape: Some(Box::new(object(&[("id", prop("string", true))]))),
                ..Default::default()
            }),
        };
        let errors = run(&shape, json!([{ "id": "1" }, {}]), false);
        assert_eq!(
            errors,
            vec![ArgError::Missing {
                field: "createRequest[1].id".into()
            }]
        );
    }

    #[test]
    fn every_bad_row_is_reported_in_one_pass() {
        // One 400 naming all three, not three round trips.
        let shape = ParamShape::Array {
            items: Box::new(NestedParam {
                param_type: "object".into(),
                shape: Some(Box::new(object(&[("id", prop("string", true))]))),
                ..Default::default()
            }),
        };
        assert_eq!(run(&shape, json!([{}, {}, {}]), false).len(), 3);
    }

    #[test]
    fn a_value_of_the_wrong_kind_is_not_descended_into() {
        // The shape describes a structure; it does not assert one. A string
        // where an object is declared is the upstream's business — rejecting it
        // here is the false-400 the parent module refuses to produce.
        let shape = object(&[("objectType", prop("string", true))]);
        assert!(run(&shape, json!("contacts"), false).is_empty());
        assert!(run(&shape, json!([1, 2]), false).is_empty());
    }

    #[test]
    fn relaxation_spreads_inward_and_covers_unknown_keys_and_enums() {
        let shape = object(&[(
            "objectType",
            NestedParam {
                param_type: "string".into(),
                enum_values: Some(vec!["contacts".into()]),
                ..Default::default()
            },
        )]);
        let value = json!({ "objectType": "tickets", "undeclared": 1 });
        assert_eq!(run(&shape, value.clone(), false).len(), 2);
        assert!(run(&shape, value, true).is_empty());
    }

    #[test]
    fn relaxation_still_enforces_a_nested_required_field() {
        // Same rule the top level applies: `required` is a statement about the
        // operation, not about how completely we transcribed it.
        let shape = object(&[("objectType", prop("string", true))]);
        assert_eq!(run(&shape, json!({}), true).len(), 1);
    }

    #[test]
    fn a_sub_schema_may_open_itself_under_a_strict_action() {
        let shape = ParamShape::Object {
            properties: BTreeMap::from([("known".to_string(), prop("string", false))]),
            additional_properties: true,
        };
        assert!(run(&shape, json!({ "anything": 1 }), false).is_empty());
    }

    #[test]
    fn a_sub_schema_cannot_re_close_what_its_action_opened() {
        // `additionalProperties` is absent far more often than it is
        // deliberately `false`, so honouring a re-tightening would mostly mean
        // honouring an omission.
        let shape = object(&[("known", prop("string", false))]);
        assert!(run(&shape, json!({ "anything": 1 }), true).is_empty());
    }

    #[test]
    fn a_null_nested_value_reads_as_absent() {
        let shape = object(&[("objectType", prop("string", true))]);
        assert_eq!(run(&shape, json!({ "objectType": null }), false).len(), 1);
    }

    #[test]
    fn validation_stops_at_the_element_cap_without_failing_the_call() {
        let shape = ParamShape::Array {
            items: Box::new(NestedParam {
                param_type: "object".into(),
                shape: Some(Box::new(object(&[("id", prop("string", true))]))),
                ..Default::default()
            }),
        };
        let rows: Vec<Value> = (0..MAX_VALIDATED_ELEMENTS + 50)
            .map(|_| json!({}))
            .collect();
        assert_eq!(
            run(&shape, Value::Array(rows), false).len(),
            MAX_VALIDATED_ELEMENTS
        );
    }
}
