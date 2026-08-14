//! The failure vocabulary of argument validation: [`ArgError`], how it
//! renders, and the typo-suggestion helper behind [`ArgError::Unknown`].

use serde_json::Value;

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

/// Render a value for an error message: a string yields its raw contents (no
/// surrounding quotes), anything else its compact JSON form.
pub(super) fn value_to_plain_string(v: &Value) -> String {
    match v.as_str() {
        Some(s) => s.to_string(),
        None => v.to_string(),
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

pub(super) fn key(e: &ArgError) -> (u8, &str) {
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
pub(in crate::openapi) fn closest_match<'a>(
    target: &str,
    candidates: impl Iterator<Item = &'a str>,
) -> Option<String> {
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
