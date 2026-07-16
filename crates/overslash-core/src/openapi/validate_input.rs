//! Runtime argument validation against a lowered `input_schema`.
//!
//! The OpenAPI loader compiles every action's `input_schema` into a
//! `HashMap<String, ActionParam>` (see `extract::lower_input_schema`). At
//! call time we re-use that compiled shape to enforce the contract the
//! template advertised: required fields must be present, unknown keys are
//! rejected (mirrors `additionalProperties: false`), and `enum` members must
//! be respected.
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
    /// A supplied value is not one of the param's declared `enum` members
    /// (after case-normalization). `value` is the offending value (stringified
    /// for non-string inputs); `allowed` is the full member list.
    NotInEnum {
        field: String,
        value: String,
        allowed: Vec<String>,
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
            ArgError::NotInEnum {
                field,
                value,
                allowed,
            } => {
                let list = allowed
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("argument `{field}` value `{value}` is not one of: {list}")
            }
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

    // Enum contract for supplied values. Runs after `coerce_args` has had its
    // chance to case-normalize, so a value still outside the member set is a
    // genuine miss. `null` is handled by the required pass above.
    for (name, p) in params {
        let Some(v) = args.get(name) else { continue };
        if v.is_null() {
            continue;
        }
        // An empty member list is not a constraint: the loader collects enum
        // members via `as_str`, so a numeric/boolean enum (e.g. `[200, 404]`)
        // lowers to `Some(vec![])`. Treat that as unconstrained rather than
        // rejecting every value against an empty allow-list.
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

    if errors.is_empty() {
        Ok(())
    } else {
        // Stable ordering helps callers (and tests) — Missing, then Unknown,
        // then NotInEnum, each alphabetical by field.
        errors.sort_by(|a, b| key(a).cmp(&key(b)));
        Err(errors)
    }
}

/// Render a value for an error message: a string yields its raw contents (no
/// surrounding quotes), anything else its compact JSON form.
fn value_to_plain_string(v: &Value) -> String {
    match v.as_str() {
        Some(s) => s.to_string(),
        None => v.to_string(),
    }
}

/// Rewrite caller-supplied argument keys that match a declared param's
/// `aliases` to that param's canonical name, in place, so a well-known synonym
/// (`to` for `recipient`, `body` for `text`) is accepted instead of rejected
/// as an unknown argument.
///
/// Only keys that are *not themselves* declared params are candidates — a real
/// param name is never treated as another param's alias, so a declared field
/// always wins over an alias that happens to collide with it. An alias claimed
/// by two different params is ambiguous and left untouched (the caller gets the
/// usual unknown-argument error, with a Levenshtein suggestion). When the
/// caller supplied both the alias and the canonical key, the canonical value
/// wins and the alias is dropped.
///
/// Call this *first* — before [`apply_defaults`], [`coerce_args`], and
/// [`validate_args`] — so the rest of the pipeline (defaults, coercion,
/// validation, resolution, the approval replay payload) only ever sees
/// canonical names. When `params` is empty (no declared contract) this is a
/// no-op: without a schema there are no canonical names to rewrite toward.
pub fn apply_aliases(params: &HashMap<String, ActionParam>, args: &mut HashMap<String, Value>) {
    if params.is_empty() {
        return;
    }

    // alias → canonical, where `None` marks an alias claimed by more than one
    // param (ambiguous — never rewritten). Aliases that collide with a real
    // param name are skipped entirely: the declared field wins.
    let mut alias_map: HashMap<&str, Option<&str>> = HashMap::new();
    for (canonical, p) in params {
        for a in &p.aliases {
            if params.contains_key(a) {
                continue;
            }
            alias_map
                .entry(a.as_str())
                // Only a *different* param claiming the same alias is
                // ambiguous. A duplicate within one param's own list
                // (`aliases: [to, to]`) still resolves to that one param —
                // re-asserting the same canonical must not poison it to `None`.
                .and_modify(|slot| {
                    if *slot != Some(canonical.as_str()) {
                        *slot = None;
                    }
                })
                .or_insert(Some(canonical.as_str()));
        }
    }
    if alias_map.is_empty() {
        return;
    }

    // Collect first (can't mutate `args` while iterating its keys). Sorted so a
    // caller that redundantly supplies two aliases for the same field resolves
    // deterministically — same value approved, stored, and executed every time.
    let mut rewrites: Vec<(String, String)> = args
        .keys()
        .filter(|k| !params.contains_key(k.as_str()))
        .filter_map(|k| match alias_map.get(k.as_str()) {
            Some(Some(canonical)) => Some((k.clone(), (*canonical).to_string())),
            _ => None,
        })
        .collect();
    rewrites.sort();

    for (alias, canonical) in rewrites {
        let Some(val) = args.remove(&alias) else {
            continue;
        };
        // Canonical wins when both were supplied — insert only if absent.
        args.entry(canonical).or_insert(val);
    }
}

/// Fill `args` with each declared param's `default` where the caller omitted
/// it (key absent) or passed an explicit null. Applies to params of any
/// `required`-ness and any location — OpenAPI treats a `default` as the value
/// used when the field is not supplied. Mutates `args` in place.
///
/// Call this *before* [`validate_args`] so a `required` param carrying a
/// default is no longer reported as missing, and before request resolution so
/// the default flows into the outgoing path/query/body like any other value.
pub fn apply_defaults(params: &HashMap<String, ActionParam>, args: &mut HashMap<String, Value>) {
    for (name, p) in params {
        let Some(default) = &p.default else { continue };
        let absent = args.get(name).is_none_or(Value::is_null);
        if absent {
            args.insert(name.clone(), default.clone());
        }
    }
}

/// Repair the obvious, fixable argument-shape problems in place so a
/// well-intentioned call succeeds instead of burning an approval on a knowable
/// failure. Best-effort: anything it can't safely coerce is left untouched for
/// [`validate_args`] to reject.
///
/// Two nudges per supplied value:
/// 1. **Scalar type** — toward the param's declared type: a number/bool sent to
///    a `string` param is stringified (`612616872` → `"612616872"`); a numeric
///    string sent to an `integer`/`number` param is parsed; `"true"`/`"false"`
///    sent to a `boolean` param becomes a bool.
/// 2. **Enum** — a string that matches a declared `enum` member only up to case
///    is normalized to the canonical member (`"html"` → `"HTML"`), but only when
///    the match is unambiguous.
///
/// Params with an unspecified (empty) `param_type` are never scalar-coerced —
/// they are the `anyOf`/`oneOf`/untyped case, where guessing a target type
/// could corrupt a legitimately non-string value.
///
/// Call this *after* [`apply_defaults`] and *before* [`validate_args`] and
/// request resolution, so the coerced value is what gets validated, approved,
/// stored in the replay payload, and executed.
pub fn coerce_args(params: &HashMap<String, ActionParam>, args: &mut HashMap<String, Value>) {
    for (name, p) in params {
        let Some(original) = args.get(name).cloned() else {
            continue;
        };
        if original.is_null() {
            continue;
        }
        let mut v = original.clone();
        if let Some(scalar) = coerce_scalar(&p.param_type, &v) {
            v = scalar;
        }
        if let Some(canon) = coerce_enum(p.enum_values.as_deref(), &v) {
            v = canon;
        }
        if v != original {
            args.insert(name.clone(), v);
        }
    }
}

/// Nudge a scalar `v` toward `param_type`. Returns `Some` only when a coercion
/// was applied. An empty/unrecognized `param_type` never coerces.
fn coerce_scalar(param_type: &str, v: &Value) -> Option<Value> {
    match param_type {
        "string" => match v {
            Value::Number(n) => Some(Value::String(n.to_string())),
            Value::Bool(b) => Some(Value::String(b.to_string())),
            _ => None,
        },
        "integer" => v
            .as_str()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .map(Value::from),
        "number" => v
            .as_str()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number),
        "boolean" => match v.as_str().map(str::trim) {
            Some("true") => Some(Value::Bool(true)),
            Some("false") => Some(Value::Bool(false)),
            _ => None,
        },
        _ => None,
    }
}

/// Case-normalize a string enum value to its canonical member. Returns `Some`
/// only when `v` is a string that isn't already a member but uniquely matches
/// one ignoring case.
fn coerce_enum(allowed: Option<&[String]>, v: &Value) -> Option<Value> {
    let allowed = allowed?;
    let s = v.as_str()?;
    if allowed.iter().any(|a| a == s) {
        return None;
    }
    let mut matches = allowed.iter().filter(|a| a.eq_ignore_ascii_case(s));
    match (matches.next(), matches.next()) {
        (Some(canon), None) => Some(Value::String(canon.clone())),
        _ => None,
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
        ArgError::NotInEnum { field, .. } => (2, field.as_str()),
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
            aliases: Vec::new(),
            location: crate::types::ParamLocation::Body,
        }
    }

    fn p_alias(t: &str, required: bool, aliases: &[&str]) -> ActionParam {
        ActionParam {
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            ..p(t, required)
        }
    }

    fn p_default(t: &str, required: bool, default: Value) -> ActionParam {
        ActionParam {
            default: Some(default),
            ..p(t, required)
        }
    }

    fn p_enum(members: &[&str], required: bool) -> ActionParam {
        ActionParam {
            enum_values: Some(members.iter().map(|s| s.to_string()).collect()),
            ..p("string", required)
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
    fn default_satisfies_required() {
        // A `required` param carrying a default (e.g. `calendarId: primary`)
        // is omittable: applying defaults fills it, so validation passes.
        let s = schema(&[("calendarId", p_default("string", true, json!("primary")))]);
        let mut a = args(&[]);
        apply_defaults(&s, &mut a);
        assert_eq!(a.get("calendarId"), Some(&json!("primary")));
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn default_fills_null() {
        let s = schema(&[("calendarId", p_default("string", true, json!("primary")))]);
        let mut a = args(&[("calendarId", json!(null))]);
        apply_defaults(&s, &mut a);
        assert_eq!(a.get("calendarId"), Some(&json!("primary")));
    }

    #[test]
    fn caller_value_wins_over_default() {
        let s = schema(&[("calendarId", p_default("string", true, json!("primary")))]);
        let mut a = args(&[("calendarId", json!("work@group.calendar.google.com"))]);
        apply_defaults(&s, &mut a);
        assert_eq!(
            a.get("calendarId"),
            Some(&json!("work@group.calendar.google.com"))
        );
    }

    #[test]
    fn no_default_still_missing() {
        // Regression guard: a required param without a default is still
        // reported missing after the defaults pass runs.
        let s = schema(&[("recipient", p("string", true))]);
        let mut a = args(&[]);
        apply_defaults(&s, &mut a);
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
                ArgError::Missing { field }
                | ArgError::Unknown { field, .. }
                | ArgError::NotInEnum { field, .. } => field.as_str(),
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

    // ── coercion ──────────────────────────────────────────────────────

    #[test]
    fn coerce_int_to_string_for_string_param() {
        // The burned `chat_id: 612616872` case: an integer sent to a `string`
        // param is stringified so the call succeeds instead of failing upstream.
        let s = schema(&[("chat_id", p("string", true))]);
        let mut a = args(&[("chat_id", json!(612616872))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("chat_id"), Some(&json!("612616872")));
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn coerce_bool_to_string_for_string_param() {
        let s = schema(&[("flag", p("string", false))]);
        let mut a = args(&[("flag", json!(true))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("flag"), Some(&json!("true")));
    }

    #[test]
    fn coerce_enum_case_normalizes_to_canonical_member() {
        // The burned `parse_mode` case: a case-only mismatch is repaired.
        let s = schema(&[(
            "parse_mode",
            p_enum(&["HTML", "Markdown", "MarkdownV2"], false),
        )]);
        let mut a = args(&[("parse_mode", json!("html"))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("parse_mode"), Some(&json!("HTML")));
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn coerce_numeric_string_to_integer() {
        let s = schema(&[("count", p("integer", false))]);
        let mut a = args(&[("count", json!("5"))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("count"), Some(&json!(5)));
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn coerce_string_to_boolean() {
        let s = schema(&[("enabled", p("boolean", false))]);
        let mut a = args(&[("enabled", json!("false"))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("enabled"), Some(&json!(false)));
    }

    #[test]
    fn coerce_leaves_unspecified_type_untouched() {
        // Empty param_type (anyOf/untyped) must never be scalar-coerced — the
        // integer stays an integer.
        let s = schema(&[("val", p("", false))]);
        let mut a = args(&[("val", json!(42))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("val"), Some(&json!(42)));
        assert!(validate_args(&s, &a).is_ok());
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
        assert!(validate_args(&s, &args(&[("labelIds", json!(["INBOX", "UNREAD"]))])).is_ok());
        assert!(validate_args(&s, &args(&[("labelIds", json!({"nested": 1}))])).is_ok());
    }

    #[test]
    fn non_numeric_string_for_integer_param_is_not_rejected() {
        // Coercion can't turn "abc" into an integer, and we don't reject on
        // type — the value flows through untouched.
        let s = schema(&[("count", p("integer", false))]);
        let mut a = args(&[("count", json!("abc"))]);
        coerce_args(&s, &mut a);
        assert!(validate_args(&s, &a).is_ok());
        assert_eq!(a.get("count"), Some(&json!("abc")));
    }

    #[test]
    fn not_in_enum_reported_for_non_member() {
        let s = schema(&[("parse_mode", p_enum(&["HTML", "Markdown"], false))]);
        let mut a = args(&[("parse_mode", json!("Fancy"))]);
        coerce_args(&s, &mut a);
        let err = validate_args(&s, &a).unwrap_err();
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
        assert!(validate_args(&s, &args(&[("status", json!(404))])).is_ok());
    }

    #[test]
    fn unspecified_type_accepts_any_scalar() {
        // Empty param_type is unconstrained — any value passes.
        let s = schema(&[("val", p("", false))]);
        assert!(validate_args(&s, &args(&[("val", json!(7))])).is_ok());
        assert!(validate_args(&s, &args(&[("val", json!(true))])).is_ok());
        assert!(validate_args(&s, &args(&[("val", json!("x"))])).is_ok());
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
        let err = validate_args(&s, &a).unwrap_err();
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

    // ── apply_aliases ─────────────────────────────────────────────────

    #[test]
    fn alias_key_rewritten_to_canonical() {
        let s = schema(&[("recipient", p_alias("string", true, &["to", "dest"]))]);
        let mut a = args(&[("to", json!("x@s.whatsapp.net"))]);
        apply_aliases(&s, &mut a);
        assert_eq!(a.get("recipient"), Some(&json!("x@s.whatsapp.net")));
        assert!(!a.contains_key("to"));
        // And the rewritten call now validates clean.
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn canonical_key_untouched_and_wins_over_alias() {
        let s = schema(&[("recipient", p_alias("string", true, &["to"]))]);
        // Both supplied: canonical value wins, alias dropped.
        let mut a = args(&[("recipient", json!("canon")), ("to", json!("alias"))]);
        apply_aliases(&s, &mut a);
        assert_eq!(a.get("recipient"), Some(&json!("canon")));
        assert!(!a.contains_key("to"));
    }

    #[test]
    fn declared_field_never_shadowed_by_an_alias() {
        // `body` is a real param AND an alias of `text` — the real field wins:
        // a `body` arg stays put, it is not stolen into `text`.
        let s = schema(&[
            ("text", p_alias("string", false, &["body"])),
            ("body", p("string", false)),
        ]);
        let mut a = args(&[("body", json!("hello"))]);
        apply_aliases(&s, &mut a);
        assert_eq!(a.get("body"), Some(&json!("hello")));
        assert!(!a.contains_key("text"));
    }

    #[test]
    fn duplicate_alias_within_one_param_still_applies() {
        // A param that lists the same alias twice is NOT ambiguous — both point
        // at the same canonical field, so the alias must still be rewritten.
        let s = schema(&[("recipient", p_alias("string", true, &["to", "to"]))]);
        let mut a = args(&[("to", json!("x@s.whatsapp.net"))]);
        apply_aliases(&s, &mut a);
        assert_eq!(a.get("recipient"), Some(&json!("x@s.whatsapp.net")));
        assert!(!a.contains_key("to"));
    }

    #[test]
    fn ambiguous_alias_left_untouched() {
        // `x` is claimed by two params — refuse to guess. The caller gets the
        // normal unknown-argument path (with a Levenshtein suggestion).
        let s = schema(&[
            ("alpha", p_alias("string", false, &["x"])),
            ("beta", p_alias("string", false, &["x"])),
        ]);
        let mut a = args(&[("x", json!(1))]);
        apply_aliases(&s, &mut a);
        assert_eq!(a.get("x"), Some(&json!(1)));
        assert!(!a.contains_key("alpha") && !a.contains_key("beta"));
        assert!(matches!(
            validate_args(&s, &a).unwrap_err().as_slice(),
            [ArgError::Unknown { field, .. }] if field == "x"
        ));
    }

    #[test]
    fn non_alias_unknown_key_is_left_for_validation() {
        let s = schema(&[("recipient", p_alias("string", true, &["to"]))]);
        let mut a = args(&[("recipient", json!("a")), ("bogus", json!(1))]);
        apply_aliases(&s, &mut a);
        assert!(a.contains_key("bogus"));
    }

    #[test]
    fn no_schema_is_a_noop() {
        let s: HashMap<String, ActionParam> = HashMap::new();
        let mut a = args(&[("to", json!("x"))]);
        apply_aliases(&s, &mut a);
        assert_eq!(a.get("to"), Some(&json!("x")));
    }

    #[test]
    fn alias_pipeline_feeds_defaults_and_coercion() {
        // `chat` aliases `chat_id` (a string param); the caller sends a number
        // under the alias. After alias→canonical rewrite, coercion still fires
        // on the canonical key, so the value lands stringified.
        let s = schema(&[("chat_id", p_alias("string", true, &["chat"]))]);
        let mut a = args(&[("chat", json!(612616872))]);
        apply_aliases(&s, &mut a);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("chat_id"), Some(&json!("612616872")));
        assert!(validate_args(&s, &a).is_ok());
    }
}
