//! The nested shape of an `object` or `array` action parameter.
//!
//! Templates are authored as OpenAPI 3.1 / JSON Schema, so a parameter's inner
//! structure has always been *writable*. It was simply not read: both lowering
//! sites reduced every parameter to `(type, enum, default)` and dropped
//! `properties` and `items` on the floor, which left twenty-one shipped
//! `object` params and three arrays of objects describing their contract in
//! prose and nothing else — and left eight templates (`holded`'s invoice lines,
//! `gmail`/`outlook`'s message envelopes) authoring a full schema that no
//! caller ever saw.
//!
//! [`ParamShape`] is that missing half, and it is deliberately a **reduced**
//! JSON Schema rather than the whole vocabulary. It carries exactly what the
//! three consumers need: what a model must know to build a valid argument, what
//! [`validate_args`](crate::openapi::validate_args) can check without guessing,
//! and what the dashboard can render as a form. `format`, `minimum`,
//! `oneOf`/`anyOf`, `$ref` and the rest are not modelled, because nothing would
//! read them — the same reason the top-level parameter type carries no more
//! than it does.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How deep [`ParamShape`] lowering descends before it stops.
///
/// A schema is a tree an author controls, and every level of it is carried in
/// memory for the life of the process and projected onto API responses. Five is
/// past anything the shipped corpus writes (the deepest, HubSpot's
/// `createRequest`, is three) and far short of a depth that would make the
/// compiled registry expensive. A level below the cap lowers as a bare
/// `object`/`array` — i.e. exactly today's behaviour — so the cap degrades
/// rather than fails.
pub const MAX_PARAM_SCHEMA_DEPTH: usize = 5;

/// The inner structure of an `object` or `array` parameter.
///
/// `None` on a parameter means the template authored no sub-schema, which stays
/// unconstrained exactly as every parameter is today. This type is only ever
/// reached through a parameter that declared one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParamShape {
    /// `type: object` with a `properties` block.
    Object {
        /// Property name → its own shape.
        ///
        /// A `BTreeMap` rather than a `HashMap` because this is serialized onto
        /// API responses: iteration order would otherwise make byte-identical
        /// requests return differently-ordered JSON, which is the same reason
        /// the search projection sorts its parameters explicitly.
        properties: BTreeMap<String, NestedParam>,
        /// JSON Schema's own `additionalProperties`. When true, an undeclared
        /// key inside this object is forwarded rather than rejected — the
        /// nested twin of the action-level relaxation, and settled by whichever
        /// declaration is nearest.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        additional_properties: bool,
    },
    /// `type: array` with a declared `items` schema.
    ///
    /// An array whose `items` is absent, or is an empty schema, lowers to
    /// `None` rather than to an `Array` of an empty `NestedParam`: "we do not
    /// know" and "we know it is untyped" would validate identically but read
    /// very differently to anyone looking at the compiled template. An `items`
    /// that names only a type is kept — "each element is an object" says more
    /// than `array` alone.
    Array { items: Box<NestedParam> },
}

impl ParamShape {
    /// The declared properties of an object shape, or `None` for an array.
    pub fn properties(&self) -> Option<&BTreeMap<String, NestedParam>> {
        match self {
            ParamShape::Object { properties, .. } => Some(properties),
            ParamShape::Array { .. } => None,
        }
    }

    /// The item schema of an array shape, or `None` for an object.
    pub fn items(&self) -> Option<&NestedParam> {
        match self {
            ParamShape::Array { items } => Some(items),
            ParamShape::Object { .. } => None,
        }
    }

    /// Whether an undeclared key inside this shape is forwarded rather than
    /// rejected. Always false for an array, which has no keys of its own.
    pub fn additional_properties(&self) -> bool {
        match self {
            ParamShape::Object {
                additional_properties,
                ..
            } => *additional_properties,
            ParamShape::Array { .. } => false,
        }
    }
}

/// One property inside a [`ParamShape`].
///
/// Deliberately **not**
/// [`ActionParam`](crate::types::ActionParam). A nested property cannot carry
/// `location` (it lives inside a body value, not on the wire in its own right),
/// `instance_config` (the service-instance form is a flat key/value map),
/// `aliases` (`apply_aliases` rewrites the top-level argument map only),
/// `resolve` (a resolver is keyed by parameter name and answers into
/// `.resolved.<name>`), or `sql_field` (already a *path* that descends into an
/// object parameter). Modelling those fields here would advertise behaviour
/// nothing implements, which is worse than not offering it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NestedParam {
    /// `"string"`, `"integer"`, …, or `""` when no concrete type is declared.
    ///
    /// The empty string is the same sentinel the top-level parameter type uses:
    /// it means `anyOf`/`oneOf`/untyped, and it keeps type-shaped logic from
    /// guessing `"string"` and false-rejecting a legitimately polymorphic value.
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub param_type: String,
    /// Whether the enclosing object's `required` list names this property.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// This property's own nested shape, when it is itself an object or array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Box<ParamShape>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nested(param_type: &str) -> NestedParam {
        NestedParam {
            param_type: param_type.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn object_shape_round_trips_without_its_empty_halves() {
        // Every optional field is skipped when empty, so a compiled template
        // that declares a plain string property serializes as the one key that
        // carries information. This is what keeps the shape affordable on
        // `/v1/search`, where it is emitted per action per instance.
        let shape = ParamShape::Object {
            properties: BTreeMap::from([("objectType".to_string(), nested("string"))]),
            additional_properties: false,
        };
        assert_eq!(
            serde_json::to_value(&shape).unwrap(),
            json!({ "properties": { "objectType": { "type": "string" } } })
        );
    }

    #[test]
    fn array_shape_round_trips() {
        let shape = ParamShape::Array {
            items: Box::new(nested("string")),
        };
        let v = serde_json::to_value(&shape).unwrap();
        assert_eq!(v, json!({ "items": { "type": "string" } }));
        assert_eq!(
            serde_json::from_value::<ParamShape>(v).unwrap(),
            shape,
            "an untagged enum must not read an array shape back as an object"
        );
    }

    #[test]
    fn accessors_answer_only_for_their_own_variant() {
        let obj = ParamShape::Object {
            properties: BTreeMap::new(),
            additional_properties: true,
        };
        let arr = ParamShape::Array {
            items: Box::new(nested("")),
        };
        assert!(obj.properties().is_some() && obj.items().is_none());
        assert!(arr.items().is_some() && arr.properties().is_none());
        // An array has no keys of its own, so it can never relax a check that
        // only applies to keys.
        assert!(obj.additional_properties());
        assert!(!arr.additional_properties());
    }

    #[test]
    fn recursion_survives_a_round_trip() {
        let shape = ParamShape::Object {
            properties: BTreeMap::from([(
                "objects".to_string(),
                NestedParam {
                    param_type: "array".into(),
                    required: true,
                    shape: Some(Box::new(ParamShape::Array {
                        items: Box::new(NestedParam {
                            param_type: "object".into(),
                            shape: Some(Box::new(ParamShape::Object {
                                properties: BTreeMap::from([("id".to_string(), nested("string"))]),
                                additional_properties: false,
                            })),
                            ..Default::default()
                        }),
                    })),
                    ..Default::default()
                },
            )]),
            additional_properties: false,
        };
        let v = serde_json::to_value(&shape).unwrap();
        assert_eq!(serde_json::from_value::<ParamShape>(v).unwrap(), shape);
    }
}
