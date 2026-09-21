//! Runtime argument validation against a lowered `input_schema`.
//!
//! The OpenAPI loader compiles every action's `input_schema` into a
//! `HashMap<String, ActionParam>` (see `extract::lower_input_schema`). At
//! call time we re-use that compiled shape to enforce the contract the
//! template advertised: required fields must be present, unknown keys are
//! rejected (mirrors `additionalProperties: false`), and `enum` members must
//! be respected.
//!
//! The same three checks run at every *depth* a parameter declares a shape for
//! (see [`nested`]), so an action whose contract is a nested object gets the
//! same self-correctable 400 its top-level fields get, naming the field by its
//! full path. A parameter whose template authored no sub-schema is
//! unconstrained inside, exactly as every parameter was before shapes existed.
//!
//! That closed world is the default, not a law. An action carrying
//! `x-overslash-additional-properties: true` passes `additional_properties`
//! here, which drops *both* the unknown-key rejection and the `enum`
//! membership check — the key is named for the JSON Schema keyword but is
//! deliberately wider than it, because a template we transcribed from a
//! `tools/list` snapshot or a partially-documented upstream is as likely to
//! have a stale enum as a missing parameter. `required` is enforced either
//! way: it is a statement about the operation, not about how completely we
//! wrote it down.
//!
//! The checks run in two passes. [`coerce_args`] first repairs the obvious
//! fixable cases in place — an integer where a `string` is declared is
//! stringified, an enum value is case-normalized to its canonical member — so
//! a well-intentioned call just works instead of burning an approval on a
//! knowable failure. [`validate_args`] then rejects what coercion could not
//! rescue — a value outside a declared `enum` — with a 400 the agent can
//! self-correct.
//!
//! Type *rejection* is deliberately out of scope: hand-written service schemas
//! under-specify types (e.g. Gmail's `labelIds` is declared `string` but
//! legitimately accepts an array that the query renderer expands to repeated
//! pairs), so rejecting a value purely because its JSON type differs from the
//! declared one produces false 400s on valid calls. We coerce the safe scalar
//! cases and otherwise let the value through. Params whose type is unspecified
//! (empty `param_type` — the `anyOf`/`oneOf`/untyped case) are never coerced.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::ActionParam;

mod coerce;
mod error;
mod nested;
#[cfg(test)]
mod test_helpers;

pub use coerce::{apply_aliases, apply_defaults, coerce_args};
pub use error::{ArgError, format_errors};

// Re-exported for `super::lint`, which suggests a canonical extension name for a
// near-miss the same way argument validation suggests a parameter name.
pub(in crate::openapi) use error::closest_match;
use error::{key, value_to_plain_string};

/// Validate `args` against `params` (a lowered `input_schema`).
///
/// Returns `Ok(())` when every required field is present and every
/// supplied key is declared. Otherwise returns the full set of issues so
/// the caller can report all problems in one round-trip.
///
/// When `params` is empty (e.g. the action declared no input contract),
/// validation is a no-op — we cannot reject arguments without a schema to
/// compare against.
///
/// `additional_properties` is the action's
/// [`ServiceAction::additional_properties`](crate::types::ServiceAction::additional_properties).
/// When set, an undeclared key is forwarded instead of rejected and a declared
/// `enum` becomes advisory. The required pass is unaffected.
pub fn validate_args(
    params: &HashMap<String, ActionParam>,
    args: &HashMap<String, Value>,
    additional_properties: bool,
) -> Result<(), Vec<ArgError>> {
    if params.is_empty() {
        return Ok(());
    }

    let mut errors = Vec::new();

    for (name, p) in params {
        if p.required {
            match args.get(name) {
                Some(v) if !v.is_null() => {}
                _ => errors.push(ArgError::Missing {
                    field: name.clone(),
                }),
            }
        }
    }

    // Undeclared keys. Skipped entirely when the action opted out of the
    // closed world — the cost is the `did you mean` suggestion on a typo,
    // which is the trade the template author made knowingly.
    if !additional_properties {
        let mut expected: Vec<String> = params.keys().cloned().collect();
        expected.sort();
        for name in args.keys() {
            if !params.contains_key(name) {
                errors.push(ArgError::Unknown {
                    field: name.clone(),
                    suggestion: closest_match(name, params.keys().map(String::as_str)),
                    expected: expected.clone(),
                });
            }
        }
    }

    // Enum contract for supplied values. Runs after `coerce_args` has had its
    // chance to case-normalize, so a value still outside the member set is a
    // genuine miss. `null` is handled by the required pass above.
    //
    // Relaxed along with undeclared keys: an enum we transcribed is a snapshot
    // of the upstream's members at transcription time, and the same template
    // that cannot name every parameter cannot be trusted to have a current
    // member list either. `coerce_args` still case-normalizes a near-miss onto
    // its canonical member, so the common case keeps its repair.
    if !additional_properties {
        for (name, p) in params {
            let Some(v) = args.get(name) else { continue };
            if v.is_null() {
                continue;
            }
            // An empty member list is not a constraint: the loader collects
            // enum members via `as_str`, so a numeric/boolean enum (e.g.
            // `[200, 404]`) lowers to `Some(vec![])`. Treat that as
            // unconstrained rather than rejecting every value against an empty
            // allow-list.
            if let Some(allowed) = p.enum_values.as_ref().filter(|a| !a.is_empty()) {
                let is_member = v.as_str().is_some_and(|s| allowed.iter().any(|a| a == s));
                if !is_member {
                    errors.push(ArgError::NotInEnum {
                        field: name.clone(),
                        value: value_to_plain_string(v),
                        allowed: allowed.clone(),
                    });
                }
            }
        }
    }

    // Nested shapes, for every supplied value whose param declared one. Runs
    // after the flat passes so the errors an agent reads are ordered
    // outside-in: a missing top-level `createRequest` is reported before
    // anything about what should have been inside it.
    for (name, p) in params {
        let (Some(shape), Some(v)) = (p.shape.as_deref(), args.get(name)) else {
            continue;
        };
        if v.is_null() {
            continue;
        }
        nested::validate_nested(shape, v, additional_properties, name, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        // Stable ordering helps callers (and tests) — Missing, then Unknown,
        // then NotInEnum, each alphabetical by field.
        errors.sort_by(|a, b| key(a).cmp(&key(b)));
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use super::test_helpers::{args, p, p_enum, schema};

    #[test]
    fn ok_when_all_required_present_and_no_unknowns() {
        let s = schema(&[
            ("recipient", p("string", true)),
            ("text", p("string", true)),
            ("reply_to_id", p("string", false)),
        ]);
        let a = args(&[
            ("recipient", json!("x@s.whatsapp.net")),
            ("text", json!("hi")),
        ]);
        assert!(validate_args(&s, &a, false).is_ok());
    }

    #[test]
    fn missing_required_reported() {
        let s = schema(&[
            ("recipient", p("string", true)),
            ("text", p("string", true)),
        ]);
        let a = args(&[("text", json!("hi"))]);
        let err = validate_args(&s, &a, false).unwrap_err();
        assert_eq!(
            err,
            vec![ArgError::Missing {
                field: "recipient".into()
            }]
        );
    }

    #[test]
    fn null_value_treated_as_missing() {
        let s = schema(&[("recipient", p("string", true))]);
        let a = args(&[("recipient", json!(null))]);
        let err = validate_args(&s, &a, false).unwrap_err();
        assert_eq!(
            err,
            vec![ArgError::Missing {
                field: "recipient".into()
            }]
        );
    }

    #[test]
    fn unknown_key_reports_candidates_for_semantic_miss() {
        // The exact case that triggered this fix: caller passed `jid` for
        // an action whose schema declares `recipient`. They share no
        // characters, so Levenshtein offers no suggestion — but the
        // candidate list still tells the agent what's accepted.
        let s = schema(&[
            ("recipient", p("string", true)),
            ("text", p("string", true)),
        ]);
        let a = args(&[("jid", json!("x@s.whatsapp.net")), ("text", json!("hi"))]);
        let err = validate_args(&s, &a, false).unwrap_err();
        assert!(
            err.iter()
                .any(|e| matches!(e, ArgError::Missing { field } if field == "recipient"))
        );
        let unknown = err
            .iter()
            .find(|e| matches!(e, ArgError::Unknown { field, .. } if field == "jid"))
            .unwrap_or_else(|| panic!("expected Unknown(jid), got {err:?}"));
        match unknown {
            ArgError::Unknown {
                expected,
                suggestion,
                ..
            } => {
                assert_eq!(suggestion, &None, "jid→recipient is not a typo");
                assert_eq!(expected, &vec!["recipient".to_string(), "text".to_string()]);
            }
            _ => unreachable!(),
        }
        // The rendered message names the available fields.
        let msg = unknown.message();
        assert!(
            msg.contains("`recipient`") && msg.contains("`text`"),
            "expected candidates in error, got: {msg}"
        );
    }

    #[test]
    fn unknown_key_suggests_when_levenshtein_close() {
        // Real typo: `recipien` (missing 't') → distance 1 from `recipient`.
        let s = schema(&[("recipient", p("string", true))]);
        let a = args(&[("recipien", json!("x"))]);
        let err = validate_args(&s, &a, false).unwrap_err();
        let unknown = err
            .iter()
            .find(|e| matches!(e, ArgError::Unknown { field, .. } if field == "recipien"))
            .unwrap();
        match unknown {
            ArgError::Unknown { suggestion, .. } => {
                assert_eq!(suggestion.as_deref(), Some("recipient"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn empty_schema_is_noop() {
        // No declared params → can't validate, accept anything.
        let s: HashMap<String, ActionParam> = HashMap::new();
        let a = args(&[("anything", json!(1))]);
        assert!(validate_args(&s, &a, false).is_ok());
    }

    #[test]
    fn errors_ordered_missing_then_unknown_alphabetical() {
        let s = schema(&[("a", p("string", true)), ("b", p("string", true))]);
        let a = args(&[("z", json!(1)), ("y", json!(2))]);
        let err = validate_args(&s, &a, false).unwrap_err();
        let fields: Vec<&str> = err
            .iter()
            .map(|e| match e {
                ArgError::Missing { field }
                | ArgError::Unknown { field, .. }
                | ArgError::NotInEnum { field, .. } => field.as_str(),
            })
            .collect();
        assert_eq!(fields, vec!["a", "b", "y", "z"]);
    }

    // ── enum rejection ────────────────────────────────────────────────

    #[test]
    fn wrong_json_type_is_not_rejected() {
        // Type rejection is deliberately out of scope: service schemas
        // under-specify types (e.g. Gmail's `labelIds` is `type: string` but
        // legitimately accepts an array). A value whose JSON type differs from
        // the declared scalar type passes through — coercion handles the safe
        // cases, everything else is the upstream's business.
        let s = schema(&[("labelIds", p("string", false))]);
        assert!(
            validate_args(
                &s,
                &args(&[("labelIds", json!(["INBOX", "UNREAD"]))]),
                false
            )
            .is_ok()
        );
        assert!(validate_args(&s, &args(&[("labelIds", json!({"nested": 1}))]), false).is_ok());
    }

    #[test]
    fn not_in_enum_reported_for_non_member() {
        let s = schema(&[("parse_mode", p_enum(&["HTML", "Markdown"], false))]);
        let mut a = args(&[("parse_mode", json!("Fancy"))]);
        coerce_args(&s, &mut a);
        let err = validate_args(&s, &a, false).unwrap_err();
        assert_eq!(
            err,
            vec![ArgError::NotInEnum {
                field: "parse_mode".into(),
                value: "Fancy".into(),
                allowed: vec!["HTML".into(), "Markdown".into()],
            }]
        );
    }

    #[test]
    fn empty_enum_list_is_unconstrained() {
        // A numeric enum (`enum: [200, 404, 500]`) lowers to `Some(vec![])`
        // because the loader keeps only string members. That empty list must
        // NOT reject every value — the param is effectively unconstrained.
        let param = ActionParam {
            enum_values: Some(vec![]),
            ..p("integer", false)
        };
        let s = schema(&[("status", param)]);
        assert!(validate_args(&s, &args(&[("status", json!(404))]), false).is_ok());
    }

    #[test]
    fn unspecified_type_accepts_any_scalar() {
        // Empty param_type is unconstrained — any value passes.
        let s = schema(&[("val", p("", false))]);
        assert!(validate_args(&s, &args(&[("val", json!(7))]), false).is_ok());
        assert!(validate_args(&s, &args(&[("val", json!(true))]), false).is_ok());
        assert!(validate_args(&s, &args(&[("val", json!("x"))]), false).is_ok());
    }

    #[test]
    fn errors_ordered_enum_after_missing_unknown() {
        // Sort order: Missing, Unknown, NotInEnum.
        let s = schema(&[
            ("req", p("string", true)),
            ("mode", p_enum(&["a", "b"], false)),
        ]);
        let a = args(&[
            ("zzz", json!(1)),       // Unknown
            ("mode", json!("nope")), // NotInEnum
        ]);
        let err = validate_args(&s, &a, false).unwrap_err();
        let tags: Vec<&str> = err
            .iter()
            .map(|e| match e {
                ArgError::Missing { .. } => "missing",
                ArgError::Unknown { .. } => "unknown",
                ArgError::NotInEnum { .. } => "enum",
            })
            .collect();
        assert_eq!(tags, vec!["missing", "unknown", "enum"]);
    }

    // --- `additional_properties: true` -------------------------------------

    #[test]
    fn relaxed_allows_undeclared_keys() {
        let s = schema(&[("q", p("string", false))]);
        let a = args(&[("q", json!("hi")), ("undeclared", json!("forwarded"))]);
        assert!(
            validate_args(&s, &a, false).is_err(),
            "strict still rejects"
        );
        assert!(validate_args(&s, &a, true).is_ok());
    }

    #[test]
    fn relaxed_allows_enum_non_members() {
        let s = schema(&[("mode", p_enum(&["a", "b"], false))]);
        let a = args(&[("mode", json!("c"))]);
        assert!(
            validate_args(&s, &a, false).is_err(),
            "strict still rejects"
        );
        assert!(validate_args(&s, &a, true).is_ok());
    }

    #[test]
    fn relaxed_still_enforces_required() {
        // The whole point of the split: `required` is a statement about the
        // operation, not about how completely we transcribed it.
        let s = schema(&[
            ("req", p("string", true)),
            ("mode", p_enum(&["a", "b"], false)),
        ]);
        let a = args(&[("mode", json!("off-list")), ("extra", json!(1))]);
        let err = validate_args(&s, &a, true).unwrap_err();
        assert!(
            matches!(err.as_slice(), [ArgError::Missing { field }] if field == "req"),
            "expected only the missing-required error, got {err:?}",
        );
    }

    #[test]
    fn relaxed_reports_every_missing_required_at_once() {
        let s = schema(&[("a", p("string", true)), ("b", p("string", true))]);
        let err = validate_args(&s, &args(&[("junk", json!(1))]), true).unwrap_err();
        assert_eq!(err.len(), 2, "both requireds reported: {err:?}");
    }

    #[test]
    fn relaxed_is_still_a_noop_without_a_schema() {
        // `params.is_empty()` short-circuits before the flag is consulted, so
        // the two agree on the action that declares nothing.
        let s = schema(&[]);
        let a = args(&[("anything", json!(1))]);
        assert!(validate_args(&s, &a, false).is_ok());
        assert!(validate_args(&s, &a, true).is_ok());
    }
}
