//! Server-side jq filter applied to upstream HTTP response bodies.
//!
//! Callers attach `filter: { lang: "jq", expr: "..." }` to an execute
//! request and the gateway returns the filter's output alongside the
//! original body (never replacing it).

use std::time::Duration;

use jaq_core::{
    Compiler, Ctx, Vars,
    data::JustLut,
    load::{Arena, File, Loader},
};
use jaq_json::{Val, read};
use overslash_core::types::{FilterErrorKind, FilteredBody};
use serde::{Deserialize, Serialize};

pub const FILTER_LANG_JQ: &str = "jq";

/// Hard cap on the number of values a single filter invocation may emit.
/// Stops `range(0; 1e9)`-style CPU bombs that would otherwise burn the
/// whole timeout window producing trivial outputs.
const MAX_FILTER_OUTPUT_VALUES: usize = 10_000;

/// Tagged wire form of a response filter. Future languages add new
/// variants; the discriminant is `lang`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "lang", rename_all = "lowercase")]
pub enum ResponseFilter {
    Jq { expr: String },
}

impl ResponseFilter {
    pub fn lang(&self) -> &'static str {
        match self {
            Self::Jq { .. } => FILTER_LANG_JQ,
        }
    }

    pub fn expr(&self) -> &str {
        match self {
            Self::Jq { expr } => expr,
        }
    }
}

/// Validate filter syntax without an upstream call. Returns `Err(message)`
/// on parse/compile error so the route handler can surface a 400 before
/// burning any upstream quota. Compiles + discards — recompiled inside the
/// blocking task at execution time, which is microseconds and acceptable.
pub fn validate_syntax(filter: &ResponseFilter) -> Result<(), String> {
    match filter {
        ResponseFilter::Jq { expr } => compile_and_discard(expr),
    }
}

fn compile_and_discard(expr: &str) -> Result<(), String> {
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let loader = Loader::new(defs);
    let arena = Arena::default();
    let program = File {
        code: expr,
        path: (),
    };
    let modules = loader.load(&arena, program).map_err(format_load_errors)?;
    Compiler::<&str, JustLut<Val>>::default()
        .with_funs(
            jaq_core::funs::<JustLut<Val>>()
                .chain(jaq_std::funs::<JustLut<Val>>())
                .chain(jaq_json::funs::<JustLut<Val>>()),
        )
        .compile(modules)
        .map(|_| ())
        .map_err(format_compile_errors)
}

fn format_load_errors<P>(errs: jaq_core::load::Errors<&str, P>) -> String {
    use jaq_core::load::Error;
    let mut out = String::new();
    for (_file, err) in errs {
        match err {
            Error::Lex(es) => {
                for (expect, src) in es {
                    out.push_str(&format!(
                        "lex error: expected {} near `{}`; ",
                        expect.as_str(),
                        short(src)
                    ));
                }
            }
            Error::Parse(es) => {
                for (expect, _tok) in es {
                    out.push_str(&format!("parse error: expected {}; ", expect.as_str()));
                }
            }
            Error::Io(es) => {
                for (path, msg) in es {
                    out.push_str(&format!("io error reading `{}`: {msg}; ", short(path)));
                }
            }
        }
    }
    if out.is_empty() {
        out.push_str("invalid jq filter");
    }
    out.trim_end_matches([';', ' ']).to_string()
}

fn format_compile_errors<P>(
    errs: jaq_core::load::Errors<&str, P, Vec<jaq_core::compile::Error<&str>>>,
) -> String {
    let mut out = String::new();
    for (_file, file_errs) in errs {
        for (term, _undef) in file_errs {
            out.push_str(&format!("undefined symbol `{}`; ", short(term)));
        }
    }
    if out.is_empty() {
        out.push_str("filter failed to compile");
    }
    out.trim_end_matches([';', ' ']).to_string()
}

fn short(s: &str) -> String {
    // Truncate by chars, not bytes — `&s[..60]` panics on a non-char-boundary
    // index, which is reachable any time the source contains multi-byte UTF-8
    // (cyrillic, CJK, emoji, etc.) within the first 60 bytes.
    let s = s.trim();
    let mut iter = s.chars();
    let prefix: String = iter.by_ref().take(60).collect();
    if iter.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

/// Run the filter against `body` with a wall-clock `timeout`. Always
/// returns a `FilteredBody` envelope — even error cases — so the caller
/// always learns the lang they asked for and the original size.
pub async fn apply(filter: ResponseFilter, body: String, timeout: Duration) -> FilteredBody {
    match filter {
        ResponseFilter::Jq { expr } => apply_jq(expr, body, timeout).await,
    }
}

async fn apply_jq(expr: String, body: String, timeout: Duration) -> FilteredBody {
    let original_bytes = body.len();
    let lang = FILTER_LANG_JQ.to_string();

    let join = tokio::task::spawn_blocking(move || run_jq_blocking(&expr, &body));

    let res = match tokio::time::timeout(timeout, join).await {
        Ok(Ok(res)) => res,
        Ok(Err(_join_err)) => Err(JqErr::RuntimeError("filter task panicked".to_string())),
        Err(_elapsed) => {
            // Note: the blocking task continues running until it hits the
            // iteration cap or naturally exits — tokio cannot cancel it
            // mid-flight. The cap bounds the damage window.
            return FilteredBody::Error {
                lang,
                kind: FilterErrorKind::Timeout,
                message: format!("filter exceeded {}ms", timeout.as_millis()),
                original_bytes,
            };
        }
    };

    match res {
        Ok((values, filtered_bytes)) => FilteredBody::Ok {
            lang,
            values,
            original_bytes,
            filtered_bytes,
        },
        Err(JqErr::OutputOverflow(n)) => FilteredBody::Error {
            lang,
            kind: FilterErrorKind::OutputOverflow,
            message: format!("filter produced more than {n} values"),
            original_bytes,
        },
        Err(JqErr::BodyNotJson(msg)) => FilteredBody::Error {
            lang,
            kind: FilterErrorKind::BodyNotJson,
            message: cap_message(msg),
            original_bytes,
        },
        Err(JqErr::RuntimeError(msg)) => FilteredBody::Error {
            lang,
            kind: FilterErrorKind::RuntimeError,
            message: cap_message(msg),
            original_bytes,
        },
    }
}

/// Internal error variants for the blocking jq task. Distinct from the
/// public `FilterErrorKind` so we can carry messages through the boundary.
/// Exposed to sibling modules (e.g. `services::disclosure`) so they can
/// reuse `run_jq_blocking` without duplicating the jaq compile plumbing.
pub(crate) enum JqErr {
    BodyNotJson(String),
    RuntimeError(String),
    OutputOverflow(usize),
}

pub(crate) fn run_jq_blocking(
    expr: &str,
    body: &str,
) -> Result<(Vec<serde_json::Value>, usize), JqErr> {
    let input = read::parse_single(body.as_bytes())
        .map_err(|e| JqErr::BodyNotJson(format!("upstream body is not JSON: {e}")))?;

    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let loader = Loader::new(defs);
    let arena = Arena::default();
    let program = File {
        code: expr,
        path: (),
    };
    let modules = loader
        .load(&arena, program)
        // Validated up front in `validate_syntax`; if this hits, the filter
        // expression mutated underneath us — surface as runtime error.
        .map_err(|_| JqErr::RuntimeError("filter failed to re-parse".to_string()))?;
    let filter = Compiler::<&str, JustLut<Val>>::default()
        .with_funs(
            jaq_core::funs::<JustLut<Val>>()
                .chain(jaq_std::funs::<JustLut<Val>>())
                .chain(jaq_json::funs::<JustLut<Val>>()),
        )
        .compile(modules)
        .map_err(|_| JqErr::RuntimeError("filter failed to recompile".to_string()))?;

    let ctx = Ctx::<JustLut<Val>>::new(&filter.lut, Vars::new([]));
    let iter = filter.id.run((ctx, input)).map(jaq_core::unwrap_valr);

    let mut values = Vec::new();
    let mut filtered_bytes: usize = 0;
    for item in iter {
        if values.len() >= MAX_FILTER_OUTPUT_VALUES {
            return Err(JqErr::OutputOverflow(MAX_FILTER_OUTPUT_VALUES));
        }
        let val = item.map_err(|e| JqErr::RuntimeError(format!("{e}")))?;
        // Render via Display, then re-parse as serde_json::Value so it
        // serializes naturally as part of the API response. The roundtrip
        // is acceptable because filter outputs are intentionally small —
        // that is the point of having a filter.
        let json = val.to_string();
        filtered_bytes += json.len();
        let parsed: serde_json::Value = serde_json::from_str(&json).map_err(|e| {
            JqErr::RuntimeError(format!("could not encode filter output as JSON: {e}"))
        })?;
        values.push(parsed);
    }

    Ok((values, filtered_bytes))
}

pub(crate) fn cap_message(msg: String) -> String {
    // Char-based cap. `String::truncate` is byte-indexed and panics if the
    // boundary lands inside a multi-byte UTF-8 sequence — reachable any time
    // the upstream error message contains non-ASCII (provider error strings
    // routinely do).
    const MAX_CHARS: usize = 512;
    let mut iter = msg.chars();
    let prefix: String = iter.by_ref().take(MAX_CHARS).collect();
    if iter.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jq(expr: &str) -> ResponseFilter {
        ResponseFilter::Jq {
            expr: expr.to_string(),
        }
    }

    #[test]
    fn validate_accepts_basic_filters() {
        assert!(validate_syntax(&jq(".items[] | .id")).is_ok());
        assert!(validate_syntax(&jq(".")).is_ok());
        assert!(validate_syntax(&jq(".foo // \"default\"")).is_ok());
    }

    #[test]
    fn validate_rejects_garbage() {
        assert!(validate_syntax(&jq(".items[")).is_err());
        assert!(validate_syntax(&jq("|||")).is_err());
    }

    #[test]
    fn cap_message_does_not_panic_on_multibyte_utf8() {
        // Pre-fix bug: `String::truncate(512)` would panic when byte 512
        // landed inside a multi-byte char. With 4-byte chars, byte 512 falls
        // exactly between the 128th and 129th char — safe — so use a 3-byte
        // char (€) to land mid-char: 171 chars × 3 bytes = 513 bytes, so
        // byte 512 is the 3rd byte of the 171st char.
        let big = "€".repeat(600);
        let out = cap_message(big);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 513); // 512 chars + ellipsis
    }

    #[test]
    fn short_does_not_panic_on_multibyte_utf8() {
        // A pre-fix bug: `&s[..60]` would panic when byte 60 fell inside a
        // multi-byte char. Each "🦀" is 4 bytes, so 30 of them = 120 bytes,
        // and the 60-byte boundary lands mid-char. Char-based truncation
        // handles this cleanly.
        let crabby = "🦀".repeat(80);
        let out = short(&crabby);
        assert!(out.ends_with('…'));
        assert!(out.starts_with('🦀'));
        // Should hold exactly 60 crab chars + the ellipsis.
        assert_eq!(out.chars().count(), 61);
    }

    #[tokio::test]
    async fn apply_happy_path_collects_stream() {
        let body = r#"{"items":[{"id":1},{"id":2},{"id":3}]}"#.to_string();
        let out = apply(jq(".items[] | .id"), body, Duration::from_secs(2)).await;
        match out {
            FilteredBody::Ok { values, .. } => {
                assert_eq!(values.len(), 3);
                assert_eq!(values[0], serde_json::json!(1));
                assert_eq!(values[2], serde_json::json!(3));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_body_not_json_returns_envelope() {
        let out = apply(jq("."), "not json".to_string(), Duration::from_secs(2)).await;
        match out {
            FilteredBody::Error { kind, .. } => {
                assert!(matches!(kind, FilterErrorKind::BodyNotJson));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_output_overflow() {
        let out = apply(
            jq("range(0; 100000)"),
            "null".to_string(),
            Duration::from_secs(5),
        )
        .await;
        match out {
            FilteredBody::Error { kind, .. } => {
                assert!(matches!(kind, FilterErrorKind::OutputOverflow));
            }
            other => panic!("expected OutputOverflow, got {other:?}"),
        }
    }
}
