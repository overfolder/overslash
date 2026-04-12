//! Shared grammar primitives for `{param}` placeholders and `[optional segment]`
//! interpolation, used by both the runtime interpolator (`description.rs`) and
//! the template linter (`template_validation`).
//!
//! Keeping both consumers on the same scanner prevents the "runtime accepts X,
//! linter rejects X" drift that would otherwise be easy to introduce.

use std::ops::Range;

/// Find the byte index of the closing `]` for an opening `[` at `open_at`.
///
/// Flat-only: the grammar does not support nested `[...]` segments. A nested
/// `[` inside `[...]` is reported by [`validate_flat_brackets`] — this function
/// just returns the first `]` after `open_at`, matching the runtime interpolator.
pub(crate) fn find_closing_bracket(s: &str, open_at: usize) -> Option<usize> {
    debug_assert!(
        s.as_bytes().get(open_at).copied() == Some(b'['),
        "find_closing_bracket expects `[` at open_at"
    );
    s[open_at + 1..]
        .find(']')
        .map(|offset| open_at + 1 + offset)
}

/// Iterate `{ident}` placeholders in `s`.
///
/// Yields `(byte_range, identifier)` for each well-formed `{ident}`. Empty
/// idents (`{}`) and unclosed `{` are skipped. The byte range covers the full
/// `{ident}` including both braces.
pub(crate) fn iter_placeholders(s: &str) -> PlaceholderIter<'_> {
    PlaceholderIter { s, i: 0 }
}

pub(crate) struct PlaceholderIter<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Iterator for PlaceholderIter<'a> {
    type Item = (Range<usize>, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.s.as_bytes();
        while self.i < bytes.len() {
            if bytes[self.i] == b'{' {
                if let Some(close_off) = self.s[self.i + 1..].find('}') {
                    let start = self.i;
                    let end = self.i + 1 + close_off + 1;
                    let key = &self.s[self.i + 1..self.i + 1 + close_off];
                    self.i = end;
                    if !key.is_empty() {
                        return Some((start..end, key));
                    }
                    continue;
                }
            }
            self.i += 1;
        }
        None
    }
}

/// Validate that `[...]` optional segments in `s` are well-formed and flat.
///
/// Errors if:
/// - an opening `[` has no matching `]`
/// - a `[` appears inside another `[...]` (nesting is not supported)
/// - a stray `]` appears outside any `[...]` segment
///
/// Returns `Err(byte_offset)` pointing at the first offending byte.
pub(crate) fn validate_flat_brackets(s: &str) -> Result<(), usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                let Some(close_off) = s[i + 1..].find(']') else {
                    return Err(i);
                };
                let inner = &s[i + 1..i + 1 + close_off];
                if let Some(nested_off) = inner.find('[') {
                    return Err(i + 1 + nested_off);
                }
                i = i + 1 + close_off + 1;
            }
            b']' => return Err(i),
            _ => i += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_basic() {
        let s = "hello {name} world {x}";
        let out: Vec<_> = iter_placeholders(s).map(|(_, k)| k).collect();
        assert_eq!(out, vec!["name", "x"]);
    }

    #[test]
    fn placeholders_empty_skipped() {
        let s = "a {} b {name}";
        let out: Vec<_> = iter_placeholders(s).map(|(_, k)| k).collect();
        assert_eq!(out, vec!["name"]);
    }

    #[test]
    fn placeholders_unclosed_skipped() {
        let s = "a {unclosed";
        let out: Vec<_> = iter_placeholders(s).map(|(_, k)| k).collect();
        assert!(out.is_empty());
    }

    #[test]
    fn placeholders_span_matches() {
        let s = "pre {x} post";
        let (range, key) = iter_placeholders(s).next().unwrap();
        assert_eq!(key, "x");
        assert_eq!(&s[range], "{x}");
    }

    #[test]
    fn brackets_balanced() {
        assert!(validate_flat_brackets("a [b] c").is_ok());
        assert!(validate_flat_brackets("no brackets").is_ok());
        assert!(validate_flat_brackets("a [b] and [c {d}]").is_ok());
        assert!(validate_flat_brackets("").is_ok());
    }

    #[test]
    fn brackets_unclosed() {
        assert_eq!(validate_flat_brackets("a [b"), Err(2));
    }

    #[test]
    fn brackets_stray_close() {
        assert_eq!(validate_flat_brackets("a ] b"), Err(2));
    }

    #[test]
    fn brackets_nested() {
        // "[a [b] c]" — inner `[` at offset 3
        assert_eq!(validate_flat_brackets("[a [b] c]"), Err(3));
    }

    #[test]
    fn find_closing_bracket_basic() {
        let s = "a [b] c";
        assert_eq!(find_closing_bracket(s, 2), Some(4));
    }

    #[test]
    fn find_closing_bracket_none() {
        let s = "a [b";
        assert_eq!(find_closing_bracket(s, 2), None);
    }
}
