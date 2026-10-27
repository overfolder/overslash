//! `x-overslash-subactions` template checks: the description grammar of every
//! label the block carries, and the shapes that parse but cannot do what the
//! author meant.

use std::collections::HashMap;

use crate::description_grammar::{iter_placeholders, validate_flat_brackets};
use crate::subactions::find_enumerations;
use crate::template_validation::Issues;
use crate::types::{ActionParam, ServiceAction};

use super::action::{has_unclosed_brace, param_ident_resolvable};

/// Where a label is rendered decides what it may name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    /// Rendered once per item (`phrase`): `{item.*}` and params, no loops.
    Item,
    /// Rendered over a group of items (`summary`): may `enumerate`, and reads
    /// `{count}`; `{item.*}` outside a loop works when the group has one item.
    Group,
}

pub(super) fn check_subactions(key: &str, action: &ServiceAction, issues: &mut Issues) {
    let Some(spec) = &action.subactions else {
        return;
    };
    let base = format!("actions.{key}.subactions");
    let params = &action.params;

    if let Some(t) = &spec.summary {
        check_label(t, Label::Group, params, &format!("{base}.summary"), issues);
    }
    if let Some(t) = &spec.phrase {
        check_label(t, Label::Item, params, &format!("{base}.phrase"), issues);
    }
    check_pairing(spec.verb.is_some(), spec.phrase.is_some(), &base, issues);

    for v in &spec.variants {
        let vbase = format!("{base}.{}", v.key);
        if let Some(t) = &v.summary {
            check_label(t, Label::Group, params, &format!("{vbase}.summary"), issues);
        }
        if let Some(t) = &v.phrase {
            check_label(t, Label::Item, params, &format!("{vbase}.phrase"), issues);
        }
        check_pairing(v.verb.is_some(), v.phrase.is_some(), &vbase, issues);
        if spec.each.is_none() && v.matches.contains("[]") {
            issues.warn(
                "subactions_match_without_each",
                format!(
                    "variant `{}` iterates an array in `match` but the block has no `each`, \
                     so the whole call is one item and a mixed batch matches nothing — \
                     declare `each` to classify per item",
                    v.key
                ),
                format!("{vbase}.match"),
            );
        }
    }
}

fn check_pairing(verb: bool, phrase: bool, path: &str, issues: &mut Issues) {
    if verb != phrase {
        issues.warn(
            "subactions_verb_without_phrase",
            "`verb` and `phrase` compose together; with only one of them the default \
             description falls back to the summary or description",
            path.to_string(),
        );
    }
}

fn check_label(
    template: &str,
    kind: Label,
    params: &HashMap<String, ActionParam>,
    path: &str,
    issues: &mut Issues,
) {
    let enums = match find_enumerations(template) {
        Ok(e) => e,
        Err(off) => {
            issues.err(
                "invalid_description_syntax",
                format!("unclosed `{{enumerate(` at byte offset {off}"),
                path.to_string(),
            );
            return;
        }
    };
    if kind == Label::Item && !enums.is_empty() {
        issues.err(
            "invalid_description_syntax",
            "a phrase describes one item and cannot `enumerate`",
            path.to_string(),
        );
    }
    // The outer text, with each loop cut out, then each loop body on its own.
    let mut outer = String::new();
    let mut last = 0;
    for (range, _) in &enums {
        outer.push_str(&template[last..range.start]);
        last = range.end;
    }
    outer.push_str(&template[last..]);

    let mut parts = vec![(outer.as_str(), kind)];
    parts.extend(enums.iter().map(|(_, inner)| (*inner, Label::Item)));
    for (text, part_kind) in parts {
        if let Err(off) = validate_flat_brackets(text) {
            issues.err(
                "unbalanced_brackets",
                format!("unbalanced or nested '[' at byte offset {off}"),
                path.to_string(),
            );
        }
        if has_unclosed_brace(text) {
            issues.err(
                "invalid_description_syntax",
                "unclosed '{' placeholder",
                path.to_string(),
            );
        }
        for (_, ident) in iter_placeholders(text) {
            let ok = ident == "item"
                || ident.starts_with("item.")
                || (ident == "count" && part_kind == Label::Group)
                || param_ident_resolvable(params, ident);
            if !ok {
                issues.err(
                    "unknown_description_param",
                    format!(
                        "placeholder {{{ident}}} is neither `item.*`{} nor a defined param",
                        if part_kind == Label::Group {
                            ", `count`"
                        } else {
                            ""
                        }
                    ),
                    path.to_string(),
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "subactions_tests.rs"]
mod tests;
