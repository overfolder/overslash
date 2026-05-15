//! Runtime argument validation against a lowered `input_schema`.
//!
//! The OpenAPI loader compiles every action's `input_schema` into a
//! `HashMap<String, ActionParam>` (see `extract::lower_input_schema`). At
//! call time we re-use that compiled shape to enforce the contract the
//! template advertised: required fields must be present, and unknown keys
//! are rejected (mirrors `additionalProperties: false`).
//!
//! Type/format/enum checking is intentionally out of scope here — the goal
//! is to catch the `jid` vs `recipient` typo class that silently rendered
//! `{recipient}` in descriptions and collapsed permission scopes to `*`.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::ActionParam;

/// One reason a call's arguments failed to match the action contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// A field listed as required was either absent or set to `null`.
    Missing { field: String },
    /// An argument key not declared in `properties`. `suggestion` is the
    /// closest declared name (Levenshtein) when one is within typo
    /// distance; `expected` is the full sorted list of declared keys,
    /// always populated so semantic-miss errors (e.g. `jid` for an action
    /// declaring `recipient`) still tell the caller what's available.
    Unknown {
        field: String,
        suggestion: Option<String>,
        expected: Vec<String>,
    },
}

impl ArgError {
    pub fn message(&self) -> String {
        match self {
            ArgError::Missing { field } => format!("missing required argument `{field}`"),
            ArgError::Unknown {
                field,
                suggestion,
                expected,
            } => match suggestion {
                Some(s) => format!("unknown argument `{field}` (did you mean `{s}`?)"),
                None => {
                    let list = expected
                        .iter()
                        .map(|s| format!("`{s}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    if list.is_empty() {
                        format!("unknown argument `{field}`")
                    } else {
                        format!("unknown argument `{field}` (expected one of: {list})")
                    }
                }
            },
        }
    }
}

/// Validate `args` against `params` (a lowered `input_schema`).
///
/// Returns `Ok(())` when every required field is present and every
/// supplied key is declared. Otherwise returns the full set of issues so
/// the caller can report all problems in one round-trip.
///
/// When `params` is empty (e.g. the action declared no input contract),
/// validation is a no-op — we cannot reject arguments without a schema to
/// compare against.
pub fn validate_args(
    params: &HashMap<String, ActionParam>,
    args: &HashMap<String, Value>,
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

    if errors.is_empty() {
        Ok(())
    } else {
        // Stable ordering helps callers (and tests) — Missing first by
        // field name, then Unknown by field name.
        errors.sort_by(|a, b| key(a).cmp(&key(b)));
        Err(errors)
    }
}

/// Format a list of errors into a single human-readable line.
pub fn format_errors(errors: &[ArgError]) -> String {
    errors
        .iter()
        .map(ArgError::message)
        .collect::<Vec<_>>()
        .join("; ")
}

fn key(e: &ArgError) -> (u8, &str) {
    match e {
        ArgError::Missing { field } => (0, field.as_str()),
        ArgError::Unknown { field, .. } => (1, field.as_str()),
    }
}

/// Return the candidate within `edit_distance ≤ max(2, len/3)` of `target`,
/// preferring the lexicographically smaller name on ties. None if no
/// candidate is close enough — better to say nothing than to suggest a
/// wildly different field.
fn closest_match<'a>(target: &str, candidates: impl Iterator<Item = &'a str>) -> Option<String> {
    let max_dist = (target.len() / 3).max(2);
    let mut best: Option<(usize, &str)> = None;
    for c in candidates {
        let d = levenshtein(target, c);
        if d > max_dist {
            continue;
        }
        match best {
            None => best = Some((d, c)),
            Some((bd, bc)) if d < bd || (d == bd && c < bc) => best = Some((d, c)),
            _ => {}
        }
    }
    best.map(|(_, c)| c.to_string())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    let (n, m) = (av.len(), bv.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if av[i - 1] == bv[j - 1] { 0 } else { 1 };
            curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(t: &str, required: bool) -> ActionParam {
        ActionParam {
            param_type: t.into(),
            required,
            description: String::new(),
            enum_values: None,
            default: None,
            resolve: None,
        }
    }

    fn schema(entries: &[(&str, ActionParam)]) -> HashMap<String, ActionParam> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn args(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

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
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn missing_required_reported() {
        let s = schema(&[
            ("recipient", p("string", true)),
            ("text", p("string", true)),
        ]);
        let a = args(&[("text", json!("hi"))]);
        let err = validate_args(&s, &a).unwrap_err();
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
        let err = validate_args(&s, &a).unwrap_err();
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
        let err = validate_args(&s, &a).unwrap_err();
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
        let err = validate_args(&s, &a).unwrap_err();
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
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn errors_ordered_missing_then_unknown_alphabetical() {
        let s = schema(&[("a", p("string", true)), ("b", p("string", true))]);
        let a = args(&[("z", json!(1)), ("y", json!(2))]);
        let err = validate_args(&s, &a).unwrap_err();
        let fields: Vec<&str> = err
            .iter()
            .map(|e| match e {
                ArgError::Missing { field } | ArgError::Unknown { field, .. } => field.as_str(),
            })
            .collect();
        assert_eq!(fields, vec!["a", "b", "y", "z"]);
    }

    #[test]
    fn format_errors_combines_messages() {
        let errs = vec![
            ArgError::Missing {
                field: "recipient".into(),
            },
            ArgError::Unknown {
                field: "jid".into(),
                suggestion: Some("recipient".into()),
                expected: vec!["recipient".into(), "text".into()],
            },
        ];
        let s = format_errors(&errs);
        assert!(s.contains("missing required argument `recipient`"));
        assert!(s.contains("unknown argument `jid` (did you mean `recipient`?)"));
        assert!(s.contains(';'));
    }
}
