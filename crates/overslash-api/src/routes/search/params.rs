//! The model-facing projection of an action's parameter contract.
//!
//! Lives beside the search route because `/v1/search` is where a model meets an
//! action for the first time: the row it reads is what it builds its call from,
//! and every field left out of it is a field the model has to guess. That makes
//! this a context-budget surface — the caps here are the reason the projection
//! is not simply the compiled parameter map.

use serde::Serialize;

use overslash_core::types::{NestedParam, ParamShape, ServiceAction};

/// The model-facing projection of an [`ServiceAction`] parameter.
///
/// Deliberately not `ActionParam` itself: that type also carries `resolve`,
/// `sql_field`, `sql_database` and `instance_config`, which are gateway
/// plumbing the caller neither supplies nor benefits from seeing.
///
/// Recursive, because an `object`/`array` parameter whose inner shape the
/// caller cannot see is one the caller has to guess at — and a guess costs a
/// round trip, or an upstream 400 *after* an approval was burned. The recursion
/// is bounded twice over (see [`MAX_PROJECTED_DEPTH`] and
/// [`MAX_PROJECTED_NODES`]), because this is emitted per action per instance
/// across up to a hundred rows: it is a context-budget decision, not a display
/// one.
#[derive(Serialize)]
pub(super) struct ParamInfo {
    /// Absent on an array's `items`, which has no name of its own.
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    param_type: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    required: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<serde_json::Value>,
    /// The declared properties of an `object`, required-first then
    /// alphabetical like the top level.
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<ParamInfo>>,
    /// The declared element schema of an `array`.
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<Box<ParamInfo>>,
    /// Set when a budget cut the shape short, so a caller knows the absence of
    /// a field means "not shown here" rather than "not accepted". Without it a
    /// model would read a trimmed object as a complete one and build its
    /// argument against a contract that is missing pieces.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
}

/// Longest parameter description carried into a search result.
///
/// Every row in a response holds up to this much per parameter, so the cap
/// is a context-budget decision, not a display one. The widest action in the
/// shipped registry declares 10 parameters, which bounds a row's parameter
/// block at roughly 2 KB and a default 20-row response well under what the
/// action's own descriptions already cost.
const MAX_PARAM_DESCRIPTION_CHARS: usize = 160;

/// How many levels of a parameter's shape reach a search row.
///
/// Shallower than the lowering cap on purpose: a search row is the place a
/// model decides *which* action to call and roughly how, not the place it
/// reads a full specification. Three levels covers every shape the shipped
/// corpus declares (HubSpot's `createRequest` is exactly three) and anything
/// deeper is reachable on the action-detail endpoint, which is not
/// context-budgeted.
const MAX_PROJECTED_DEPTH: usize = 3;

/// How many nested nodes one parameter may contribute to a row.
///
/// The depth cap alone does not bound a *wide* schema — a single object with
/// eighty properties is one level deep — so the two caps bound different
/// things and both are needed. A node budget rather than a byte budget because
/// it is decided without serializing anything, and because the thing actually
/// worth rationing is fields a model has to read, not bytes.
const MAX_PROJECTED_NODES: usize = 24;

/// Project an action's parameters for the model.
///
/// Ordering is explicit — required first, then alphabetical — because
/// `ServiceAction.params` is a `HashMap`, and emitting its iteration order
/// would make byte-identical requests return differently-ordered JSON.
/// Required-first also front-loads what the caller cannot omit.
pub(super) fn param_infos(action: &ServiceAction) -> Vec<ParamInfo> {
    let mut out: Vec<ParamInfo> = action
        .params
        .iter()
        // `instance-config` params are pinned per service instance by an org
        // admin and merged in under the caller's args at execution time. A
        // caller has no business supplying them, so listing them here would
        // only invite a wrong one.
        .filter(|(_, p)| !p.instance_config)
        .map(|(name, p)| {
            // Each parameter gets its own node budget rather than sharing one
            // across the action: a row whose first parameter happens to be
            // elaborate must not blank out the rest.
            let mut budget = MAX_PROJECTED_NODES;
            let (properties, items, truncated) = project_shape(p.shape.as_deref(), 1, &mut budget);
            ParamInfo {
                name: name.clone(),
                param_type: p.param_type.clone(),
                required: p.required,
                description: clamp_chars(&p.description, MAX_PARAM_DESCRIPTION_CHARS),
                enum_values: p.enum_values.clone(),
                default: p.default.clone(),
                properties,
                items,
                truncated,
            }
        })
        .collect();
    sort_params(&mut out);
    out
}

/// Required first, then alphabetical — at every level, for the same reason it
/// applies at the top: the maps behind this are unordered, and emitting their
/// iteration order would make byte-identical requests return
/// differently-ordered JSON.
fn sort_params(params: &mut [ParamInfo]) {
    params.sort_by(|a, b| {
        b.required
            .cmp(&a.required)
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Project a parameter's shape into the recursive halves of [`ParamInfo`].
///
/// Returns `(properties, items, truncated)`. `truncated` is true when either
/// budget stopped the walk, and it propagates up so the *parameter* is marked
/// even when the cut happened several levels down — a caller reads the flag on
/// the thing it is about to build, not on the level that ran out.
fn project_shape(
    shape: Option<&ParamShape>,
    depth: usize,
    budget: &mut usize,
) -> (Option<Vec<ParamInfo>>, Option<Box<ParamInfo>>, bool) {
    let Some(shape) = shape else {
        return (None, None, false);
    };
    if depth > MAX_PROJECTED_DEPTH {
        return (None, None, true);
    }
    match shape {
        ParamShape::Object { properties, .. } => {
            let mut out = Vec::with_capacity(properties.len());
            let mut truncated = false;
            for (name, nested) in properties {
                if *budget == 0 {
                    truncated = true;
                    break;
                }
                *budget -= 1;
                out.push(project_nested(
                    Some(name),
                    nested,
                    depth,
                    budget,
                    &mut truncated,
                ));
            }
            sort_params(&mut out);
            (Some(out), None, truncated)
        }
        ParamShape::Array { items } => {
            if *budget == 0 {
                return (None, None, true);
            }
            *budget -= 1;
            let mut truncated = false;
            let item = project_nested(None, items, depth, budget, &mut truncated);
            (None, Some(Box::new(item)), truncated)
        }
    }
}

fn project_nested(
    name: Option<&str>,
    nested: &NestedParam,
    depth: usize,
    budget: &mut usize,
    truncated: &mut bool,
) -> ParamInfo {
    let (properties, items, cut) = project_shape(nested.shape.as_deref(), depth + 1, budget);
    *truncated |= cut;
    ParamInfo {
        name: name.unwrap_or_default().to_string(),
        param_type: nested.param_type.clone(),
        required: nested.required,
        description: clamp_chars(&nested.description, MAX_PARAM_DESCRIPTION_CHARS),
        enum_values: nested.enum_values.clone(),
        default: nested.default.clone(),
        properties,
        items,
        truncated: cut,
    }
}

/// Truncate `s` to at most `max` characters, appending an ellipsis when it
/// actually cut. Cuts at a char *index* rather than a byte index — `&s[..n]`
/// panics mid-codepoint, and template descriptions are exactly the strings
/// that carry non-ASCII.
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use overslash_core::types::{ActionParam, ParamShape, ServiceAction};
    use serde_json::{Value, json};

    use super::*;

    fn nested(param_type: &str, shape: Option<ParamShape>) -> NestedParam {
        NestedParam {
            param_type: param_type.into(),
            shape: shape.map(Box::new),
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

    /// Project one action carrying a single param with `shape`.
    fn project(shape: Option<ParamShape>) -> Value {
        let mut params = HashMap::new();
        params.insert(
            "createRequest".to_string(),
            ActionParam {
                param_type: "object".into(),
                shape: shape.map(Box::new),
                ..Default::default()
            },
        );
        let action = ServiceAction {
            params,
            ..Default::default()
        };
        serde_json::to_value(param_infos(&action)).unwrap()[0].clone()
    }

    #[test]
    fn a_param_with_no_shape_projects_exactly_what_it_used_to() {
        // The whole corpus was in this state before shapes existed, and most of
        // it still is. No new keys may appear on those rows.
        let row = project(None);
        assert_eq!(row, json!({ "name": "createRequest", "type": "object" }));
    }

    #[test]
    fn nested_properties_reach_the_row_required_first() {
        let row = project(Some(object(&[
            ("note", nested("string", None)),
            (
                "objectType",
                NestedParam {
                    param_type: "string".into(),
                    required: true,
                    enum_values: Some(vec!["contacts".into()]),
                    ..Default::default()
                },
            ),
        ])));
        let props = row["properties"].as_array().unwrap();
        assert_eq!(props[0]["name"], "objectType", "required sorts first");
        assert_eq!(props[0]["enum"][0], "contacts");
        assert_eq!(props[1]["name"], "note");
        assert!(row.get("truncated").is_none());
    }

    #[test]
    fn an_array_item_is_projected_without_a_name() {
        let row = project(Some(object(&[(
            "objects",
            nested(
                "array",
                Some(ParamShape::Array {
                    items: Box::new(nested(
                        "object",
                        Some(object(&[("id", nested("string", None))])),
                    )),
                }),
            ),
        )])));
        let item = &row["properties"][0]["items"];
        assert!(item.get("name").is_none(), "an item has no name of its own");
        assert_eq!(item["properties"][0]["name"], "id");
    }

    #[test]
    fn the_depth_cap_marks_the_param_truncated() {
        // Build past MAX_PROJECTED_DEPTH and assert the caller is told the
        // shape is partial — a model reading a trimmed object as a complete
        // one would build its argument against a contract missing pieces.
        let mut shape = object(&[("leaf", nested("string", None))]);
        for _ in 0..MAX_PROJECTED_DEPTH + 1 {
            shape = object(&[("next", nested("object", Some(shape)))]);
        }
        let row = project(Some(shape));
        assert_eq!(row["truncated"], true);
    }

    #[test]
    fn the_node_cap_bounds_a_wide_schema() {
        // The depth cap alone does not bound width: one object with a hundred
        // properties is a single level deep.
        let props: BTreeMap<String, NestedParam> = (0..MAX_PROJECTED_NODES * 2)
            .map(|i| (format!("f{i:03}"), nested("string", None)))
            .collect();
        let row = project(Some(ParamShape::Object {
            properties: props,
            additional_properties: false,
        }));
        assert_eq!(
            row["properties"].as_array().unwrap().len(),
            MAX_PROJECTED_NODES
        );
        assert_eq!(row["truncated"], true);
    }

    #[test]
    fn a_long_nested_description_is_clamped_like_a_top_level_one() {
        let long = "x".repeat(MAX_PARAM_DESCRIPTION_CHARS + 50);
        let row = project(Some(object(&[(
            "objectType",
            NestedParam {
                param_type: "string".into(),
                description: long,
                ..Default::default()
            },
        )])));
        let got = row["properties"][0]["description"].as_str().unwrap();
        assert_eq!(got.chars().count(), MAX_PARAM_DESCRIPTION_CHARS + 1);
        assert!(got.ends_with('…'));
    }
}
