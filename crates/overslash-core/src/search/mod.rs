//! Keyword + fuzzy scorer for service/action discovery (SPEC §10).
//!
//! This is the deterministic, dependency-light half of `/v1/search`. It runs
//! on every candidate `(service, action)` pair regardless of whether the
//! embedding backend is enabled, and its output is blended with the embedding
//! cosine score at the endpoint level (see `crates/overslash-api/src/routes/search.rs`).
//!
//! The scorer is intentionally pure: no DB, no IO, no async. It takes a
//! [`Candidate`] (which the caller assembles from global / org / user template
//! sources) and a query string, and returns a score in `[0.0, 1.0]`.

use strsim::jaro_winkler;

use crate::types::{Risk, ServiceAction, ServiceDefinition};

/// Minimum final score to include in results. Below this it's noise —
/// single-token coincidence on a field nobody meant to match against.
pub const MIN_SCORE: f32 = 0.15;

/// Bonus applied when the caller already has an active service instance
/// connected for this template. Small enough to break ties, big enough to
/// float an instantiable-and-connected option above one that still needs
/// setup.
pub const CONNECTED_BONUS: f32 = 0.15;

/// Tiny bonus toward read actions on ties. Prefer safer option when the
/// lexical / semantic score is otherwise indistinguishable.
pub const READ_BONUS: f32 = 0.05;

/// Jaro-Winkler threshold below which a fuzzy word match doesn't contribute.
const FUZZY_THRESHOLD: f64 = 0.85;

/// A `(service, action)` pair the scorer considers. Borrows from the caller's
/// already-materialized registry / DB rows — no clones, no allocation per
/// candidate beyond whatever the scorer itself needs.
pub struct Candidate<'a> {
    pub service: &'a ServiceDefinition,
    pub action_key: &'a str,
    pub action: &'a ServiceAction,
}

/// Score a single candidate against `query`. Returns a raw `[0.0, 1.0]`
/// score before any post-rank bonuses (connected, risk). The endpoint layer
/// adds those after blending with the embedding score so weighting stays in
/// one place.
pub fn keyword_fuzzy_score(query: &str, c: &Candidate<'_>) -> f32 {
    let tokens = tokenize(query);
    if tokens.is_empty() {
        return 0.0;
    }

    // Field weights. Action-level fields dominate because queries like
    // "send an email" are about *what to do*, not *what service*. Service-
    // level fields still matter ("stripe", "gmail") so exact service hits
    // float up too.
    let fields: [(&str, f32); 6] = [
        (c.action.description.as_str(), 3.0),
        (c.action_key, 2.5),
        (c.service.display_name.as_str(), 2.0),
        (c.service.description.as_deref().unwrap_or_default(), 1.5),
        (c.service.key.as_str(), 1.0),
        (c.service.category.as_deref().unwrap_or_default(), 0.5),
    ];

    let weight_sum: f32 = fields.iter().map(|(_, w)| *w).sum();
    let mut contribution: f32 = 0.0;

    for (field, weight) in &fields {
        if field.is_empty() {
            continue;
        }
        let field_tokens = tokenize(field);
        let per_token_sum: f32 = tokens
            .iter()
            .map(|qt| token_match_strength(qt, &field_tokens))
            .sum();
        contribution += (per_token_sum / tokens.len() as f32) * weight;
    }

    (contribution / weight_sum).clamp(0.0, 1.0)
}

/// Compute the match strength for a single query token `qt` against a field.
/// Returns `[0.0, 1.0]`:
///   - 1.0 exact word match in the field
///   - 0.9 word-prefix match on any field word (query is a prefix of a
///     field word, so "email" hits "emailing")
///   - `jw` (jaro-winkler similarity) when >= FUZZY_THRESHOLD on any field word
///   - 0.0 otherwise
///
/// Word-based (not substring) so "email" matches "email" as a whole word
/// harder than it matches "emailing" — that's the interesting distinction
/// for ranking, and it avoids meaningless substring collisions.
fn token_match_strength(qt: &str, field_tokens: &[String]) -> f32 {
    if qt.is_empty() {
        return 0.0;
    }
    let mut best: f32 = 0.0;
    for ft in field_tokens {
        if ft == qt {
            return 1.0;
        }
        if ft.starts_with(qt) {
            best = best.max(0.9);
            continue;
        }
        let jw = jaro_winkler(qt, ft) as f32;
        if (jw as f64) >= FUZZY_THRESHOLD {
            best = best.max(jw);
        }
    }
    best
}

/// Split a string into lowercase word tokens. Non-alphanumeric characters
/// act as separators. Empty tokens, as well as trivial stopwords, are
/// filtered — "an", "the", "to", etc. would otherwise boost every field
/// containing them on every query.
pub fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .filter(|t| !is_stopword(t))
        .map(|t| t.to_string())
        .collect()
}

fn is_stopword(t: &str) -> bool {
    matches!(
        t,
        "a" | "an"
            | "the"
            | "to"
            | "of"
            | "in"
            | "for"
            | "on"
            | "at"
            | "by"
            | "is"
            | "and"
            | "or"
            | "my"
            | "me"
            | "i"
    )
}

/// Apply post-rank bonuses to a raw score. Kept separate from
/// [`keyword_fuzzy_score`] so callers can blend raw keyword and embedding
/// scores first, then apply the bonuses once at the end.
pub fn apply_post_bonuses(score: f32, connected: bool, risk: Risk) -> f32 {
    let mut s = score;
    if connected {
        s += CONNECTED_BONUS;
    }
    if matches!(risk, Risk::Read) {
        s += READ_BONUS;
    }
    s.clamp(0.0, 1.0 + CONNECTED_BONUS + READ_BONUS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ServiceAuth, TokenInjection};
    use std::collections::HashMap;

    fn mk_service(key: &str, display: &str, desc: Option<&str>) -> ServiceDefinition {
        ServiceDefinition {
            key: key.into(),
            display_name: display.into(),
            description: desc.map(String::from),
            hosts: vec![],
            category: None,
            auth: vec![ServiceAuth::ApiKey {
                default_secret_name: "k".into(),
                injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: None,
                },
            }],
            actions: HashMap::new(),
        }
    }

    fn mk_action(desc: &str, risk: Risk) -> ServiceAction {
        ServiceAction {
            method: "POST".into(),
            path: "/x".into(),
            description: desc.into(),
            risk,
            response_type: None,
            params: HashMap::new(),
            scope_param: None,
            required_scopes: vec![],
        }
    }

    #[test]
    fn tokenize_drops_stopwords_and_punctuation() {
        assert_eq!(
            tokenize("Send an email to John!"),
            vec!["send", "email", "john"]
        );
    }

    #[test]
    fn empty_query_scores_zero() {
        let svc = mk_service("gmail", "Gmail", None);
        let action = mk_action("Send an email", Risk::Write);
        let c = Candidate {
            service: &svc,
            action_key: "send_message",
            action: &action,
        };
        assert_eq!(keyword_fuzzy_score("", &c), 0.0);
        assert_eq!(keyword_fuzzy_score("   the an to  ", &c), 0.0);
    }

    #[test]
    fn exact_beats_prefix_and_distant_fuzzy() {
        let svc = mk_service("gmail", "Gmail", None);
        let exact = mk_action("Send an email", Risk::Write);
        let prefix = mk_action("emailing handled here", Risk::Write);
        // Distant-enough typo: below FUZZY_THRESHOLD, so won't contribute,
        // score falls to ~0. A close typo like "emale" legitimately beats a
        // prefix match because it's more likely the user's intent.
        let distant_fuzzy = mk_action("Dispatch packages via xjqpl", Risk::Write);
        let c_exact = Candidate {
            service: &svc,
            action_key: "a",
            action: &exact,
        };
        let c_prefix = Candidate {
            service: &svc,
            action_key: "b",
            action: &prefix,
        };
        let c_distant = Candidate {
            service: &svc,
            action_key: "c",
            action: &distant_fuzzy,
        };
        let q = "email";
        let s_exact = keyword_fuzzy_score(q, &c_exact);
        let s_prefix = keyword_fuzzy_score(q, &c_prefix);
        let s_distant = keyword_fuzzy_score(q, &c_distant);
        assert!(
            s_exact > s_prefix,
            "exact word match should beat prefix: {} vs {}",
            s_exact,
            s_prefix
        );
        assert!(
            s_prefix > s_distant,
            "prefix should beat distant (sub-threshold) fuzzy: {} vs {}",
            s_prefix,
            s_distant
        );
    }

    #[test]
    fn close_typo_beats_unrelated_prefix() {
        // Documents the intended behavior: a near-typo of the query token
        // ("emale" → "email", JW ≈ 0.94) legitimately outscores a prefix
        // match on a different word ("emailing"). Prefer closeness of
        // intent over lexical coincidence.
        let svc = mk_service("gmail", "Gmail", None);
        let typo = mk_action("Dispatch an emale", Risk::Write);
        let c = Candidate {
            service: &svc,
            action_key: "a",
            action: &typo,
        };
        let score = keyword_fuzzy_score("email", &c);
        assert!(
            score > MIN_SCORE,
            "close typo should still match: {}",
            score
        );
    }

    #[test]
    fn jaro_winkler_catches_typos() {
        // "calender" (common misspelling) should still match "calendar"
        let svc = mk_service("google_calendar", "Google Calendar", None);
        let action = mk_action("Create a calendar event", Risk::Write);
        let c = Candidate {
            service: &svc,
            action_key: "insert_event",
            action: &action,
        };
        let score_typo = keyword_fuzzy_score("calender event", &c);
        assert!(
            score_typo >= MIN_SCORE,
            "typo should clear MIN_SCORE, got {}",
            score_typo
        );
    }

    #[test]
    fn unrelated_query_falls_below_cutoff() {
        let svc = mk_service("stripe", "Stripe", Some("Payments"));
        let action = mk_action("Charge a credit card", Risk::Write);
        let c = Candidate {
            service: &svc,
            action_key: "create_charge",
            action: &action,
        };
        let score = keyword_fuzzy_score("xylophone quantum", &c);
        assert!(score < MIN_SCORE, "unrelated should be low, got {}", score);
    }

    #[test]
    fn action_description_weighted_above_service_name() {
        // Query matches a keyword that appears in one service's *name* and
        // another service's *action description*. Action description should
        // win because it weighs 3.0 vs display_name 2.0.
        let svc_name_hit = mk_service("email-tools", "Email Tools", None);
        let noop = mk_action("Do something unrelated", Risk::Write);
        let svc_desc_hit = mk_service("resend", "Resend", Some("Transactional"));
        let send = mk_action("Send an email to a customer", Risk::Write);
        let c_name = Candidate {
            service: &svc_name_hit,
            action_key: "noop",
            action: &noop,
        };
        let c_desc = Candidate {
            service: &svc_desc_hit,
            action_key: "send_email",
            action: &send,
        };
        let q = "email";
        assert!(
            keyword_fuzzy_score(q, &c_desc) > keyword_fuzzy_score(q, &c_name),
            "action description weighting should beat service-name weighting"
        );
    }

    #[test]
    fn apply_post_bonuses_connected_and_read() {
        let base = 0.5;
        assert!((apply_post_bonuses(base, false, Risk::Write) - 0.5).abs() < 1e-6);
        assert!((apply_post_bonuses(base, true, Risk::Write) - 0.65).abs() < 1e-6);
        assert!((apply_post_bonuses(base, false, Risk::Read) - 0.55).abs() < 1e-6);
        assert!((apply_post_bonuses(base, true, Risk::Read) - 0.70).abs() < 1e-6);
    }
}
