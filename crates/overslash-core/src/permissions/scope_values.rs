//! Resolving an action's `scope_param` entries into the values its permission
//! keys are built from.
//!
//! Most entries resolve here, purely: the param's value is the scope value, an
//! array fans out per element, an absent param contributes nothing. An entry
//! carrying an `extract` jq program cannot — jq *evaluation* lives in
//! `overslash-api` (this crate links `jaq-core` only, for static analysis), and
//! moving key derivation there would move the one mint of the key grammar out
//! of the crate that owns it.
//!
//! So the split is a typestate rather than a convention. [`ScopePlan::build`]
//! is pure and leaves extractor entries [`ScopeEntry::Pending`];
//! [`ScopePlan::finish`] refuses to produce the [`ScopeValues`] that
//! [`PermissionKey::from_service_action`](super::PermissionKey::from_service_action)
//! demands while any remain. A caller that forgets to evaluate gets a
//! compile-shaped error at the seam instead of a call gated on a scope nobody
//! computed.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::{ScopeParamRef, ScopeParams};

/// Why an `extract` produced no usable values.
///
/// Deliberately **fieldless**. jaq's runtime errors interleave static text with
/// the operands themselves, and the operand here is caller-supplied request
/// data — so this type structurally cannot carry one out, the same guarantee
/// `disclosure::classify` gets from its `&'static str` return. See D65.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeExtractError {
    /// The program did not compile. A template-validation failure that reached
    /// the request path.
    Syntax,
    /// The program ran and failed. The `&'static str` comes from a fixed
    /// classification whitelist, never from jaq's message.
    Runtime(&'static str),
    /// The evaluation exceeded its wall-clock budget.
    Timeout,
    /// More outputs than the jq evaluator will produce.
    Overflow,
    /// More scope values than one key set may carry ([`MAX_SCOPE_VALUES`]).
    TooManyValues,
    /// An output that is not a string or number. Skipping just that one would
    /// silently drop a recipient out of the authorization set.
    NonScalarOutput,
    /// An output that is empty or only whitespace, which cannot name anything.
    EmptyValue,
}

impl ScopeExtractError {
    /// A short, operand-free tag for logs and for the audit trail.
    pub fn tag(&self) -> &'static str {
        match self {
            ScopeExtractError::Syntax => "syntax",
            ScopeExtractError::Runtime(class) => class,
            ScopeExtractError::Timeout => "timeout",
            ScopeExtractError::Overflow => "overflow",
            ScopeExtractError::TooManyValues => "too_many_values",
            ScopeExtractError::NonScalarOutput => "non_scalar_output",
            ScopeExtractError::EmptyValue => "empty_value",
        }
    }
}

/// How many values one `extract` entry may contribute.
///
/// Not redundant with the jq evaluator's own output cap: every derived key is
/// matched against every rule at every level of the identity chain, and each
/// one lands on an approval card a human is expected to read. Exceeding this is
/// a **failure, not a truncation** — quietly keeping the first 64 recipients
/// would drop the rest out of the gate entirely, which is the shape of bug this
/// whole mechanism exists to remove.
pub const MAX_SCOPE_VALUES: usize = 64;

/// One `scope_param` entry's contribution, at some stage of resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEntry {
    /// Values in hand — possibly none, which is what an absent param yields.
    Ready(Vec<String>),
    /// An `extract` waiting on the evaluator.
    Pending { expr: String, input: Value },
    /// An `extract` that failed. Mints a sentinel key rather than contributing
    /// nothing, because contributing nothing would drop this param out of the
    /// gate while the other entries kept the call ungated by a fallback.
    Unextractable(ScopeExtractError),
}

/// A resolution in progress: may still contain [`ScopeEntry::Pending`].
#[derive(Debug, Clone)]
pub struct ScopePlan(Vec<(ScopeParamRef, ScopeEntry)>);

/// A completed resolution. Cannot contain a `Pending` entry, by construction —
/// the only way to build one is [`ScopePlan::finish`].
#[derive(Debug, Clone, Default)]
pub struct ScopeValues(Vec<(ScopeParamRef, ScopeEntry)>);

/// Returned when [`ScopePlan::finish`] is called with work outstanding. Carries
/// the param names so the bug names itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnevaluatedExtracts(pub Vec<String>);

impl std::fmt::Display for UnevaluatedExtracts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scope extractors were never evaluated: {}",
            self.0.join(", ")
        )
    }
}

impl ScopePlan {
    /// Resolve what can be resolved without an evaluator.
    ///
    /// The plain-entry rules are exactly the ones key derivation applied before
    /// extractors existed: an array fans out per element, a scalar stringifies,
    /// an absent param contributes nothing.
    pub fn build(scope: &ScopeParams, params: &HashMap<String, Value>) -> Self {
        ScopePlan(
            scope
                .refs()
                .iter()
                .map(|r| {
                    let entry = match (&r.extract, params.get(&r.param)) {
                        (Some(expr), Some(input)) => ScopeEntry::Pending {
                            expr: expr.clone(),
                            input: input.clone(),
                        },
                        // An extractor over a param the caller never supplied
                        // has nothing to read, and that is not a failure — it
                        // is the same "contributes nothing" an omitted plain
                        // param gets.
                        (Some(_), None) => ScopeEntry::Ready(Vec::new()),
                        (None, Some(Value::Array(items))) => {
                            ScopeEntry::Ready(items.iter().map(scope_arg).collect())
                        }
                        (None, Some(v)) => ScopeEntry::Ready(vec![scope_arg(v)]),
                        (None, None) => ScopeEntry::Ready(Vec::new()),
                    };
                    (r.clone(), entry)
                })
                .collect(),
        )
    }

    /// The entries still awaiting evaluation, by index.
    pub fn pending(&self) -> Vec<(usize, &str, &Value)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, (_, entry))| match entry {
                ScopeEntry::Pending { expr, input } => Some((i, expr.as_str(), input)),
                _ => None,
            })
            .collect()
    }

    /// Record one evaluation's outcome.
    pub fn fill(&mut self, idx: usize, outcome: Result<Vec<String>, ScopeExtractError>) {
        if let Some((_, entry)) = self.0.get_mut(idx) {
            *entry = match outcome {
                Ok(values) => ScopeEntry::Ready(values),
                Err(e) => ScopeEntry::Unextractable(e),
            };
        }
    }

    /// Finish, or name the extractors nobody ran.
    pub fn finish(self) -> Result<ScopeValues, UnevaluatedExtracts> {
        let outstanding: Vec<String> = self
            .0
            .iter()
            .filter(|(_, e)| matches!(e, ScopeEntry::Pending { .. }))
            .map(|(r, _)| r.param.clone())
            .collect();
        if outstanding.is_empty() {
            Ok(ScopeValues(self.0))
        } else {
            Err(UnevaluatedExtracts(outstanding))
        }
    }
}

impl ScopeValues {
    /// Every entry, in authored order.
    pub fn entries(&self) -> &[(ScopeParamRef, ScopeEntry)] {
        &self.0
    }

    /// Did any extractor fail? A call in this state is gated by a sentinel key
    /// rather than by the wildcard fallback.
    pub fn has_failures(&self) -> bool {
        self.0
            .iter()
            .any(|(_, e)| matches!(e, ScopeEntry::Unextractable(_)))
    }

    /// The failures, as `(param, label, error)` — for the audit line.
    pub fn failures(&self) -> Vec<(&str, &str, ScopeExtractError)> {
        self.0
            .iter()
            .filter_map(|(r, e)| match e {
                ScopeEntry::Unextractable(err) => Some((r.param.as_str(), r.label.as_str(), *err)),
                _ => None,
            })
            .collect()
    }

    /// Build directly from already-resolved values. For the many call sites
    /// (and tests) whose scope has no extractor and therefore nothing to await.
    pub fn resolved(scope: &ScopeParams, params: &HashMap<String, Value>) -> Self {
        ScopePlan::build(scope, params)
            .finish()
            .unwrap_or_else(|e| unreachable!("{e}"))
    }
}

/// Render one scope value as the `{arg}` segment. Strings pass through
/// unquoted; anything else falls back to its JSON form.
fn scope_arg(v: &Value) -> String {
    match v.as_str() {
        Some(s) => s.to_string(),
        None => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    fn extractor(param: &str, expr: &str) -> ScopeParams {
        [ScopeParamRef {
            param: param.into(),
            label: param.into(),
            extract: Some(expr.into()),
        }]
        .into_iter()
        .collect()
    }

    #[test]
    fn a_plain_entry_resolves_without_an_evaluator() {
        let plan = ScopePlan::build(&"repo".into(), &params(&[("repo", json!("a/b"))]));
        assert!(plan.pending().is_empty());
        let values = plan.finish().unwrap();
        assert_eq!(
            values.entries()[0].1,
            ScopeEntry::Ready(vec!["a/b".to_string()])
        );
    }

    #[test]
    fn an_array_still_fans_out_per_element() {
        let plan = ScopePlan::build(&"to".into(), &params(&[("to", json!(["a", "b"]))]));
        assert_eq!(
            plan.finish().unwrap().entries()[0].1,
            ScopeEntry::Ready(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn an_extractor_waits_and_names_itself() {
        let scope = extractor("toRecipients", ".[] | .address");
        let mut plan = ScopePlan::build(
            &scope,
            &params(&[("toRecipients", json!([{"address": "a@b"}]))]),
        );
        let pending = plan.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1, ".[] | .address");

        assert_eq!(
            plan.clone().finish().unwrap_err(),
            UnevaluatedExtracts(vec!["toRecipients".into()]),
            "finishing with work outstanding must fail rather than gate on nothing"
        );

        plan.fill(0, Ok(vec!["a@b".into()]));
        assert_eq!(
            plan.finish().unwrap().entries()[0].1,
            ScopeEntry::Ready(vec!["a@b".into()])
        );
    }

    #[test]
    fn an_extractor_over_an_absent_param_is_not_a_failure() {
        // Same reading an omitted optional `cc` gets: nothing to extract from
        // is nothing to contribute, not an error to gate on.
        let scope = extractor("ccRecipients", ".[] | .address");
        let plan = ScopePlan::build(&scope, &params(&[]));
        assert!(plan.pending().is_empty());
        let values = plan.finish().unwrap();
        assert!(!values.has_failures());
        assert_eq!(values.entries()[0].1, ScopeEntry::Ready(Vec::new()));
    }

    #[test]
    fn a_failed_extractor_is_recorded_with_its_class_and_no_operand() {
        let scope = extractor("p", ".a");
        let mut plan = ScopePlan::build(&scope, &params(&[("p", json!({"a": 1}))]));
        plan.fill(0, Err(ScopeExtractError::Timeout));
        let values = plan.finish().unwrap();
        assert!(values.has_failures());
        assert_eq!(
            values.failures(),
            vec![("p", "p", ScopeExtractError::Timeout)]
        );
        assert_eq!(values.failures()[0].2.tag(), "timeout");
    }
}
