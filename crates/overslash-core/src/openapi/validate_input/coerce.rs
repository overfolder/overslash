//! Argument repair passes that run before validation: alias rewriting,
//! defaults, and scalar/enum coercion.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::ActionParam;

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
/// [`validate_args`](super::validate_args) — so the rest of the pipeline (defaults, coercion,
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
/// Call this *before* [`validate_args`](super::validate_args) so a `required` param carrying a
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
/// [`validate_args`](super::validate_args) to reject.
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
/// Call this *after* [`apply_defaults`] and *before* [`validate_args`](super::validate_args) and
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
        // A single value where a list is declared. An agent reaching for
        // `to: "a@b.com"` means a one-element list, and `to: "a@b.com, c@d.com"`
        // means two — the comma form is what a human types into a mail client,
        // and the mailbox gateway splits it the same way, so both sides must
        // agree or the derived permission keys name recipients that differ from
        // the ones actually mailed.
        //
        // A string with no comma is simply wrapped. Empty segments are dropped,
        // so `"a@b.com,"` is one recipient, not one-and-a-blank. A string that
        // is entirely separators yields `[]` — `validate_args` only checks
        // presence, so that survives to the gateway, which is the layer that
        // knows an empty recipient list is unsendable.
        "array" => match v {
            Value::Array(_) => None,
            Value::String(s) => Some(Value::Array(
                s.split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(|part| Value::String(part.to_string()))
                    .collect(),
            )),
            other => Some(Value::Array(vec![other.clone()])),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::openapi::validate_input::test_helpers::{
        args, p, p_alias, p_default, p_enum, schema,
    };
    use crate::openapi::validate_input::{ArgError, validate_args};

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
    fn coerce_lone_string_to_single_element_array() {
        // `to: "a@b.com"` is what an agent reaches for when it has one
        // recipient; the declared list shape is restored before the permission
        // key is derived.
        let s = schema(&[("to", p("array", true))]);
        let mut a = args(&[("to", json!("a@b.com"))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("to"), Some(&json!(["a@b.com"])));
        assert!(validate_args(&s, &a).is_ok());
    }

    #[test]
    fn coerce_comma_string_splits_and_trims_for_array_param() {
        // The mailbox gateway splits a recipient string on commas, so this
        // side must too — otherwise the derived permission keys name a
        // recipient that differs from the ones actually mailed.
        let s = schema(&[("cc", p("array", false))]);
        let mut a = args(&[("cc", json!("a@b.com, c@d.com ,,"))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("cc"), Some(&json!(["a@b.com", "c@d.com"])));
    }

    #[test]
    fn coerce_leaves_existing_array_untouched() {
        let s = schema(&[("to", p("array", false))]);
        // A legitimate element containing a comma must survive: only the
        // *string* form is split, never an already-shaped list.
        let mut a = args(&[("to", json!(["Doe, Jane <j@d.com>"]))]);
        coerce_args(&s, &mut a);
        assert_eq!(a.get("to"), Some(&json!(["Doe, Jane <j@d.com>"])));
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
