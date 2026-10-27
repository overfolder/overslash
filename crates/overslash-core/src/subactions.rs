//! Call-time half of `x-overslash-subactions`: turning the classifier's output
//! into classified items, and items into the one-line description a reviewer
//! reads.
//!
//! The classifier itself is jq ([`SubactionSpec::classifier_program`]) and runs
//! in the API crate, which owns the jq runtime. Everything here is pure.
//!
//! ## Description grammar
//!
//! On top of the `{param}` / `[optional]` grammar of [`crate::description`]:
//!
//! - `{item.<path>}` reads the current item (its fields, its `vars`, and in a
//!   call-level summary also `verb`, `phrase` and `subaction`);
//! - `{enumerate(<template>)}` renders `<template>` once per item and joins the
//!   results as English: `A`, `A and B`, `A, B and C`, capped with
//!   `… and N more`;
//! - `{count}` is the number of items being described.
//!
//! `{item.*}` outside an `enumerate` resolves only when exactly one item is
//! being described — the common single-record call reads naturally without a
//! loop around it.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::description::interpolate_description_with_resolved;
use crate::types::{Subaction, SubactionSpec};

/// Items past this many are summarized as `and N more`.
pub const ENUMERATE_MAX_ITEMS: usize = 5;

/// One unit of work out of `each`, with the variant it matched.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifiedItem {
    /// Index into [`SubactionSpec::variants`]; `None` stays with the parent.
    pub variant: Option<usize>,
    /// The item with the matched variant's `vars` merged over its fields.
    /// Always an object: a scalar item is wrapped as `{value: …}`.
    pub item: Map<String, Value>,
}

/// Parse the classifier program's single output. `Err` is a shape the program
/// cannot produce unless the expression around it was tampered with; callers
/// treat it like any other classifier failure — unclassified.
pub fn parse_classifier_output(
    spec: &SubactionSpec,
    out: &Value,
) -> Result<Vec<ClassifiedItem>, String> {
    let arr = out
        .as_array()
        .ok_or_else(|| "classifier did not produce an array".to_string())?;
    arr.iter()
        .map(|entry| {
            let variant = match entry.get("sub") {
                None | Some(Value::Null) => None,
                Some(v) => {
                    let i = v
                        .as_u64()
                        .ok_or_else(|| "classifier `sub` is not an index".to_string())?
                        as usize;
                    if i >= spec.variants.len() {
                        return Err("classifier `sub` out of range".to_string());
                    }
                    Some(i)
                }
            };
            let mut item = match entry.get("item") {
                Some(Value::Object(m)) => m.clone(),
                Some(other) => {
                    let mut m = Map::new();
                    m.insert("value".into(), other.clone());
                    m
                }
                None => Map::new(),
            };
            if let Some(Value::Object(vars)) = entry.get("vars") {
                for (k, v) in vars {
                    item.insert(k.clone(), v.clone());
                }
            }
            Ok(ClassifiedItem { variant, item })
        })
        .collect()
}

/// `A`, `A and B`, `A, B and C`; past [`ENUMERATE_MAX_ITEMS`] the tail
/// collapses to `and N more`. English only.
pub fn english_list(parts: &[String]) -> String {
    let (shown, rest) = if parts.len() > ENUMERATE_MAX_ITEMS {
        (
            &parts[..ENUMERATE_MAX_ITEMS],
            parts.len() - ENUMERATE_MAX_ITEMS,
        )
    } else {
        (parts, 0)
    };
    if rest > 0 {
        return format!("{} and {rest} more", shown.join(", "));
    }
    match shown {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// Byte ranges of each `{enumerate(…)}` and its inner template. The closing
/// `)}` is found by paren depth, so the inner template may hold `{item.x}`
/// placeholders and balanced parentheses of its own.
pub fn find_enumerations(template: &str) -> Result<Vec<(std::ops::Range<usize>, &str)>, usize> {
    const OPEN: &str = "{enumerate(";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = template[from..].find(OPEN) {
        let start = from + off;
        let inner_start = start + OPEN.len();
        let mut depth = 1usize;
        let mut end = None;
        for (i, c) in template[inner_start..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let close = inner_start + i;
                        if template[close + 1..].starts_with('}') {
                            end = Some(close);
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = end else {
            return Err(start);
        };
        out.push((start..close + 2, &template[inner_start..close]));
        from = close + 2;
    }
    Ok(out)
}

/// Private-use code points: never typed, never produced by a substitution
/// that cares about meaning, and free of every grammar delimiter. A rendered
/// list is parked behind one while the outer template is interpolated, so a
/// `[` or `{` inside a caller's data is never re-read as grammar.
const MARK: char = '\u{E000}';

/// Render one template over a group of items.
pub fn render_group(
    template: &str,
    items: &[&Map<String, Value>],
    params: &HashMap<String, Value>,
    resolved: &HashMap<String, String>,
) -> String {
    let Ok(enums) = find_enumerations(template) else {
        // Lint rejects this; at runtime render the text rather than fail.
        return interpolate_description_with_resolved(template, params, resolved);
    };
    let mut outer = String::with_capacity(template.len());
    let mut lists = Vec::with_capacity(enums.len());
    let mut last = 0;
    for (n, (range, inner)) in enums.iter().enumerate() {
        outer.push_str(&template[last..range.start]);
        outer.push(MARK);
        outer.push_str(&n.to_string());
        outer.push(MARK);
        last = range.end;
        let parts: Vec<String> = items
            .iter()
            .map(|item| render_item(inner, item, params, resolved))
            .filter(|s| !s.trim().is_empty())
            .collect();
        lists.push(english_list(&parts));
    }
    outer.push_str(&template[last..]);

    let mut ctx = params.clone();
    ctx.insert("count".into(), Value::from(items.len()));
    if let [one] = items {
        ctx.insert("item".into(), Value::Object((*one).clone()));
    }
    let mut rendered = interpolate_description_with_resolved(&outer, &ctx, resolved);
    for (n, list) in lists.iter().enumerate() {
        rendered = rendered.replace(&format!("{MARK}{n}{MARK}"), list);
    }
    rendered
}

/// Render a per-item template (`phrase`, an `enumerate` body).
pub fn render_item(
    template: &str,
    item: &Map<String, Value>,
    params: &HashMap<String, Value>,
    resolved: &HashMap<String, String>,
) -> String {
    let mut ctx = params.clone();
    ctx.insert("item".into(), Value::Object(item.clone()));
    interpolate_description_with_resolved(template, &ctx, resolved)
        .trim()
        .to_string()
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The description of a classified call, without the ` (Service)` suffix.
///
/// Precedence, first applicable wins:
/// 1. the call-level [`SubactionSpec::summary`];
/// 2. the variant's own `summary`, when every item fell into that variant;
/// 3. the default composition — items grouped by `verb` in order of first
///    appearance, one `<Verb> <list of phrases>` clause per verb, clauses
///    joined by `; `. An item without a verb/phrase pair contributes its
///    variant's summary (or description), or `parent_label` when no variant
///    claimed it.
pub fn describe_call(
    spec: &SubactionSpec,
    items: &[ClassifiedItem],
    parent_label: &str,
    params: &HashMap<String, Value>,
    resolved: &HashMap<String, String>,
) -> String {
    let variant = |i: &ClassifiedItem| i.variant.map(|n| &spec.variants[n]);

    if let Some(summary) = &spec.summary {
        let enriched: Vec<Map<String, Value>> = items
            .iter()
            .map(|i| {
                let mut m = i.item.clone();
                let v = variant(i);
                if let Some(verb) = v.and_then(|v| v.verb.as_ref()).or(spec.verb.as_ref()) {
                    m.insert("verb".into(), Value::String(verb.clone()));
                }
                if let Some(phrase) = v.and_then(|v| v.phrase.as_ref()).or(spec.phrase.as_ref()) {
                    m.insert(
                        "phrase".into(),
                        Value::String(render_item(phrase, &i.item, params, resolved)),
                    );
                }
                m.insert(
                    "subaction".into(),
                    v.map(|v| Value::String(v.key.clone()))
                        .unwrap_or(Value::Null),
                );
                m
            })
            .collect();
        let refs: Vec<&Map<String, Value>> = enriched.iter().collect();
        return render_group(summary, &refs, params, resolved);
    }

    if let Some(first) = items.first().and_then(|i| i.variant)
        && items.iter().all(|i| i.variant == Some(first))
        && let Some(summary) = &spec.variants[first].summary
    {
        let refs: Vec<&Map<String, Value>> = items.iter().map(|i| &i.item).collect();
        return render_group(summary, &refs, params, resolved);
    }

    enum Clause<'a> {
        Verb(&'a str, Vec<String>),
        Label(String),
    }
    let mut clauses: Vec<Clause> = Vec::new();
    let mut labelled: Vec<Option<usize>> = Vec::new();
    for item in items {
        let v: Option<&Subaction> = variant(item);
        let verb = v.and_then(|v| v.verb.as_deref()).or(match v {
            Some(_) => None,
            None => spec.verb.as_deref(),
        });
        let phrase = v.and_then(|v| v.phrase.as_deref()).or(match v {
            Some(_) => None,
            None => spec.phrase.as_deref(),
        });
        if let (Some(verb), Some(phrase)) = (verb, phrase) {
            let text = render_item(phrase, &item.item, params, resolved);
            match clauses
                .iter_mut()
                .find(|c| matches!(c, Clause::Verb(v, _) if *v == verb))
            {
                Some(Clause::Verb(_, phrases)) => phrases.push(text),
                _ => clauses.push(Clause::Verb(verb, vec![text])),
            }
            continue;
        }
        // One label per variant (or one for the parent), however many items:
        // a label cannot enumerate, so repeating it would only stutter.
        if labelled.contains(&item.variant) {
            continue;
        }
        labelled.push(item.variant);
        let label = match v {
            Some(v) => {
                let group: Vec<&Map<String, Value>> = items
                    .iter()
                    .filter(|i| i.variant == item.variant)
                    .map(|i| &i.item)
                    .collect();
                render_group(
                    v.summary.as_deref().unwrap_or(&v.description),
                    &group,
                    params,
                    resolved,
                )
            }
            None => parent_label.to_string(),
        };
        clauses.push(Clause::Label(label));
    }

    let rendered: Vec<String> = clauses
        .into_iter()
        .enumerate()
        .map(|(n, c)| match c {
            Clause::Verb(verb, phrases) => {
                let verb = if n == 0 {
                    capitalize(verb)
                } else {
                    verb.to_string()
                };
                format!("{verb} {}", english_list(&phrases))
            }
            Clause::Label(label) => label,
        })
        .collect();
    if rendered.is_empty() {
        return parent_label.to_string();
    }
    rendered.join("; ")
}

/// An item as the flat params map `scope_param` resolves against.
pub fn item_params(item: &Map<String, Value>) -> HashMap<String, Value> {
    item.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[cfg(test)]
#[path = "subactions_tests.rs"]
mod tests;
