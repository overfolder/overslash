//! Lowering a JSON Schema sub-tree into a [`ParamShape`].
//!
//! One function, shared by every site that turns an authored schema into an
//! [`ActionParam`](crate::types::ActionParam): HTTP `parameters[]`,
//! `requestBody` properties, and MCP `input_schema` properties. Keeping the
//! descent in one place is what stops the three from drifting the way they
//! drifted before, when each read its own three keys and dropped the rest.
//!
//! Deliberately lenient, in the same way [`parse_resolver`] is: anything this
//! cannot represent lowers to `None` rather than to an error, because a
//! template whose sub-schema we could not read must still load and still work
//! exactly as it did before the field existed. What is *wrong* rather than
//! merely unrepresentable — `properties` on a string, an array with no `items`
//! — is reported by `template_validation`, which is the layer that exists to
//! tell an author about it.
//!
//! [`parse_resolver`]: super::params::parse_resolver

use serde_json::{Map, Value};

use crate::types::{MAX_PARAM_SCHEMA_DEPTH, NestedParam, ParamShape};

/// Lower a schema object's `properties`/`items` into a [`ParamShape`].
///
/// Returns `None` when the schema declares no inner structure this can carry:
/// a scalar, an object with no `properties`, an array with no typed `items`, a
/// `$ref` (nothing resolves those), or a level past
/// [`MAX_PARAM_SCHEMA_DEPTH`]. In every one of those cases the parameter keeps
/// the shape it had before — a bare `object`/`array` — so the cap and the
/// unsupported constructs degrade instead of failing.
pub(super) fn lower_shape(schema: Option<&Map<String, Value>>, depth: usize) -> Option<ParamShape> {
    let s = schema?;
    if depth >= MAX_PARAM_SCHEMA_DEPTH {
        return None;
    }
    // A `$ref` is not resolved anywhere in the loader, so descending into a
    // schema that only names one would invent a shape the document does not
    // state.
    if s.contains_key("$ref") {
        return None;
    }
    match s.get("type").and_then(Value::as_str) {
        Some("object") => {
            let props = s.get("properties").and_then(Value::as_object)?;
            let required: Vec<&str> = s
                .get("required")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let properties = props
                .iter()
                .filter_map(|(name, pv)| {
                    let po = pv.as_object()?;
                    Some((
                        name.clone(),
                        lower_nested(po, required.contains(&name.as_str()), depth + 1),
                    ))
                })
                .collect();
            Some(ParamShape::Object {
                properties,
                additional_properties: s
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        }
        Some("array") => {
            let items = s.get("items").and_then(Value::as_object)?;
            // An `items: {}` carries no more than the bare `array` the
            // parameter already declares, so it lowers to `None` rather than to
            // a shape whose every field is empty: "we do not know" and "we know
            // it is untyped" validate identically and read very differently.
            //
            // `items: {type: object}` — how three shipped params are written —
            // *is* kept, even though it declares no properties. "Each element
            // is an object" is strictly more than `array` alone says, and it is
            // the difference between a model sending `["a", "b"]` and sending
            // the objects the upstream wants.
            let item = lower_nested(items, false, depth + 1);
            if item == NestedParam::default() {
                return None;
            }
            Some(ParamShape::Array {
                items: Box::new(item),
            })
        }
        _ => None,
    }
}

/// Lower one property object into a [`NestedParam`], recursing through its own
/// `properties`/`items`.
fn lower_nested(prop: &Map<String, Value>, required: bool, depth: usize) -> NestedParam {
    NestedParam {
        param_type: prop
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        required,
        description: prop
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        // Members are collected via `as_str` exactly as the top level collects
        // them, so a numeric enum lowers to an empty list and is read as
        // unconstrained rather than as an allow-list nothing satisfies.
        enum_values: prop.get("enum").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        }),
        default: prop.get("default").cloned(),
        shape: lower_shape(Some(prop), depth).map(Box::new),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn lower(v: Value) -> Option<ParamShape> {
        lower_shape(Some(&obj(v)), 0)
    }

    #[test]
    fn object_properties_carry_type_required_enum_and_description() {
        let shape = lower(json!({
            "type": "object",
            "required": ["objectType"],
            "properties": {
                "objectType": {
                    "type": "string",
                    "enum": ["contacts", "companies"],
                    "description": "CRM object type."
                },
                "note": { "type": "string" }
            }
        }))
        .expect("an object with properties lowers");
        let props = shape.properties().unwrap();
        assert!(props["objectType"].required);
        assert!(!props["note"].required);
        assert_eq!(
            props["objectType"].enum_values.as_deref(),
            Some(["contacts".to_string(), "companies".to_string()].as_slice())
        );
        assert_eq!(props["objectType"].description, "CRM object type.");
    }

    #[test]
    fn array_of_objects_recurses() {
        // HubSpot's `filterGroups` shape: an array whose items are objects
        // holding an array of objects. Three levels, which is the deepest the
        // shipped corpus goes.
        let shape = lower(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "filters": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": { "propertyName": { "type": "string" } }
                        }
                    }
                }
            }
        }))
        .expect("an array with typed items lowers");
        let filters = &shape
            .items()
            .unwrap()
            .shape
            .as_ref()
            .unwrap()
            .properties()
            .unwrap()["filters"];
        let leaf = filters.shape.as_ref().unwrap().items().unwrap();
        assert!(
            leaf.shape
                .as_ref()
                .unwrap()
                .properties()
                .unwrap()
                .contains_key("propertyName")
        );
    }

    #[test]
    fn an_empty_item_schema_lowers_to_nothing() {
        // `items: {}` says nothing the bare `array` does not, and must not
        // masquerade as a known-but-empty structure.
        assert_eq!(lower(json!({ "type": "array", "items": {} })), None);
    }

    #[test]
    fn an_item_schema_that_only_names_a_type_still_lowers() {
        // `items: {type: object}` is how HubSpot's `filterGroups`, `sorts` and
        // `get_campaign_analytics.requests` are written. It declares no
        // properties, but "each element is an object" is the difference
        // between a model sending `["a","b"]` and sending what the upstream
        // wants, so it is worth carrying.
        let shape = lower(json!({ "type": "array", "items": { "type": "object" } }))
            .expect("a typed item schema lowers");
        let item = shape.items().unwrap();
        assert_eq!(item.param_type, "object");
        assert!(item.shape.is_none(), "there are no properties to carry");
    }

    #[test]
    fn an_array_of_scalars_still_lowers() {
        // `items: {type: string}` says something a bare `array` does not, so
        // unlike the opaque-object case it survives.
        let shape = lower(json!({ "type": "array", "items": { "type": "string" } }))
            .expect("a typed item schema lowers");
        assert_eq!(shape.items().unwrap().param_type, "string");
    }

    #[test]
    fn an_object_with_no_properties_lowers_to_nothing() {
        // The 21-param case: `type: object` with the contract in prose.
        assert_eq!(lower(json!({ "type": "object" })), None);
    }

    #[test]
    fn a_scalar_never_lowers_a_shape() {
        assert_eq!(
            lower(json!({ "type": "string", "properties": { "a": { "type": "string" } } })),
            None
        );
    }

    #[test]
    fn a_ref_is_not_followed() {
        assert_eq!(
            lower(json!({ "type": "object", "$ref": "#/components/schemas/Thing" })),
            None
        );
    }

    #[test]
    fn additional_properties_is_read_from_the_standard_keyword() {
        let shape = lower(json!({
            "type": "object",
            "additionalProperties": true,
            "properties": { "a": { "type": "string" } }
        }))
        .unwrap();
        assert!(shape.additional_properties());
    }

    #[test]
    fn descent_stops_at_the_depth_cap() {
        // Build one level deeper than the cap allows and assert the tail is
        // absent rather than the whole shape being refused.
        let mut leaf = json!({ "type": "object", "properties": { "leaf": { "type": "string" } } });
        for _ in 0..MAX_PARAM_SCHEMA_DEPTH {
            leaf = json!({ "type": "object", "properties": { "next": leaf } });
        }
        let mut shape = lower(leaf).expect("the outer levels still lower");
        let mut depth = 0;
        while let Some(next) = shape
            .properties()
            .and_then(|p| p.get("next"))
            .and_then(|n| n.shape.as_deref())
        {
            shape = next.clone();
            depth += 1;
        }
        assert!(
            depth < MAX_PARAM_SCHEMA_DEPTH,
            "descent ran {depth} levels, past the {MAX_PARAM_SCHEMA_DEPTH} cap"
        );
    }
}
