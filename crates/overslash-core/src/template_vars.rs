//! Deployment-supplied template variables — `${VAR}` / `${VAR:default}`.
//!
//! A service template that names a host the deployment owns (the shared
//! Mailbox Gateway, a self-hosted Metabase) cannot hardcode it: prod serves
//! `mailbox.overslash.com`, dev serves `mailbox.dev.overslash.com`, and a
//! self-hoster serves neither. Before this module the shipped
//! `services/email.yaml` pinned the prod host, so a dev deployment's default
//! `email` instances both targeted the wrong gateway and — because
//! `Config::platform_credential_for` matches the host for exact equality —
//! were denied the platform gateway key.
//!
//! ## The namespace is the security boundary
//!
//! Values come from environment variables under [`ENV_PREFIX`] and nowhere
//! else. `DATABASE_URL`, `SECRETS_ENCRYPTION_KEY`, `SIGNING_KEY` and every
//! other unprefixed var are *structurally* unreachable — there is no syntax
//! that names them.
//!
//! Expansion runs for org- and user-authored templates too, not just the
//! shipped ones, which makes the prefix load-bearing in a second way: any
//! tenant who can author a template can read every value in it, by writing
//! `${FOO}` into a `servers[].url` and reading the resolved definition back.
//! That is by design and gating a listing endpoint would be theatre —
//! **never put a secret under this prefix.** It is a non-secret-by-declaration
//! namespace, exactly like `service_instances.config` under D33.
//!
//! ## Why the parsed document, not the YAML text
//!
//! [`expand`] walks the *parsed* document's string values. Substituting into
//! YAML source instead would make a value containing `"` or a newline able to
//! restructure the document — a template-injection primitive handed to whoever
//! sets the environment. Working post-parse makes that unrepresentable rather
//! than merely validated-against.
//!
//! ## Grammar
//!
//! - `${NAME}` — `NAME` is `[A-Z][A-Z0-9_]*`. Unset and undefaulted is an
//!   error ([`UNSET_CODE`]), never a silent empty string: the failure mode we
//!   are fixing is precisely a template that quietly names the wrong host.
//! - `${NAME:default}` — the default is everything up to the closing `}` and
//!   may not contain one. `${NAME:}` is the empty string. A default belongs
//!   only on a variable that means something in a standalone deployment;
//!   `MAILBOX_HOST` deliberately has none, because a self-hoster has no
//!   Overslash gateway and `mailbox.overslash.com` would be a wrong answer
//!   rather than a safe one.
//! - `$${` renders a literal `${`.
//! - Anything else following `$` is copied verbatim, so jq expressions and
//!   shell-ish prose in a `description` don't trip the parser.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::template_validation::ValidationIssue;

/// Environment-variable prefix. `OVERSLASH_TEMPLATE_VAR_MAILBOX_HOST`
/// supplies `${MAILBOX_HOST}`.
pub const ENV_PREFIX: &str = "OVERSLASH_TEMPLATE_VAR_";

/// [`ValidationIssue::code`] for a reference with no value and no default.
pub const UNSET_CODE: &str = "template_var_unset";

/// The deployment's template variables, keyed by the name templates use
/// (prefix already stripped).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vars {
    map: BTreeMap<String, String>,
}

impl Vars {
    /// No variables configured. Every `${VAR}` without a default is an error.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Collect every `OVERSLASH_TEMPLATE_VAR_*` variable from the process
    /// environment.
    ///
    /// Entries that can't be used are dropped with a warning rather than
    /// failing the boot: an empty value (the repo-wide "unset" spelling, see
    /// `Config::from_env`), a name that isn't a legal reference, or a value
    /// carrying ASCII control characters — the last because these land in URLs
    /// and header values, where an embedded newline is a request-splitting
    /// primitive rather than a typo.
    pub fn from_env() -> Self {
        let mut map = BTreeMap::new();
        for (key, value) in std::env::vars() {
            let Some(name) = key.strip_prefix(ENV_PREFIX) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            if !is_valid_name(name) {
                tracing::warn!(
                    env = %key,
                    "template var name is not [A-Z][A-Z0-9_]* and can never be referenced; ignoring"
                );
                continue;
            }
            if value.chars().any(char::is_control) {
                tracing::warn!(
                    env = %key,
                    "template var value contains control characters; ignoring"
                );
                continue;
            }
            map.insert(name.to_string(), value);
        }
        Self { map }
    }

    /// Build from explicit pairs. Preferred over mutating the process
    /// environment in tests, which is global and races across the suite.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            map: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// Placeholder values for every variable the shipped `services/*.yaml`
    /// templates require without a default — i.e. the set a real deployment
    /// must configure.
    ///
    /// Exists so the ~10 test sites that load the shipped directory don't each
    /// carry their own copy of that list: adding a new undefaulted variable to
    /// a shipped template should be one edit here, not a hunt through failing
    /// suites. Not for production use — `from_env` is the only real source.
    #[doc(hidden)]
    pub fn for_tests() -> Self {
        Self::from_pairs([("MAILBOX_HOST", "mailbox.overslash.com")])
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.map.get(name).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.map.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// Expand every `${VAR}` reference in the document's string values, in place.
///
/// Only strings are rewritten; numbers, booleans and structure are untouched,
/// and a reference can therefore never introduce a key, an array element, or a
/// type change. Object keys are left alone too — a variable names a *value*,
/// not a field.
///
/// Returns every unresolved reference at once (rather than the first) so an
/// operator bringing up a new deployment learns all the variables they still
/// need to set from a single boot.
pub fn expand(doc: &mut Value, vars: &Vars) -> Result<(), Vec<ValidationIssue>> {
    let mut errors = Vec::new();
    walk(doc, vars, &mut String::new(), &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn walk(node: &mut Value, vars: &Vars, path: &mut String, errors: &mut Vec<ValidationIssue>) {
    match node {
        Value::String(s) => {
            // The overwhelmingly common case: a template with no references at
            // all (every third-party service). Skip the parse entirely.
            if !s.contains('$') {
                return;
            }
            if let Some(expanded) = expand_str(s, vars, path, errors) {
                *s = expanded;
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let len = push_segment(path, &i.to_string());
                walk(item, vars, path, errors);
                path.truncate(len);
            }
        }
        Value::Object(fields) => {
            for (key, value) in fields.iter_mut() {
                let len = push_segment(path, key);
                walk(value, vars, path, errors);
                path.truncate(len);
            }
        }
        _ => {}
    }
}

/// Append `segment` to the dot-path, returning the length to truncate back to.
/// Dotted, not JSON-pointer: `servers.0.url` is the shape every other
/// `ValidationIssue` in the compiler uses, and the dashboard renders it as-is.
fn push_segment(path: &mut String, segment: &str) -> usize {
    let len = path.len();
    if !path.is_empty() {
        path.push('.');
    }
    path.push_str(segment);
    len
}

/// Expand one string. Returns `None` when nothing changed, so an unreferenced
/// string keeps its allocation.
///
/// Byte indexing is safe throughout: every delimiter this scans for (`$`, `{`,
/// `}`, `:`) is ASCII, and an ASCII byte can never occur inside a multi-byte
/// UTF-8 sequence — so a match is always on a character boundary even when the
/// surrounding text (or a default value) is not ASCII.
fn expand_str(
    src: &str,
    vars: &Vars,
    path: &str,
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i] != b'$' {
            // Copy through to the next `$` in one slice rather than per byte.
            let next = bytes[i + 1..]
                .iter()
                .position(|b| *b == b'$')
                .map_or(bytes.len(), |off| i + 1 + off);
            out.push_str(&src[i..next]);
            i = next;
            continue;
        }

        // `$${` is the escape for a literal `${`.
        if bytes[i..].starts_with(b"$${") {
            out.push_str("${");
            i += 3;
            changed = true;
            continue;
        }

        match parse_reference(src, i) {
            Some(Reference { name, default, end }) => {
                match vars.get(name).or(default) {
                    Some(value) => out.push_str(value),
                    None => {
                        errors.push(ValidationIssue::new(
                            UNSET_CODE,
                            format!(
                                "template variable `{name}` is not set and declares no default; \
                                 set `{ENV_PREFIX}{name}` on this deployment or write \
                                 `${{{name}:<default>}}`"
                            ),
                            path,
                        ));
                        // Keep the reference verbatim so a partially-expanded
                        // string never reaches a caller as if it had resolved.
                        out.push_str(&src[i..end]);
                    }
                }
                i = end;
                changed = true;
            }
            None => {
                // Not a reference — a bare `$`, or `${` followed by something
                // that isn't a legal name. Copy the `$` and carry on.
                out.push('$');
                i += 1;
            }
        }
    }

    changed.then_some(out)
}

struct Reference<'a> {
    name: &'a str,
    default: Option<&'a str>,
    /// Byte index just past the closing `}`.
    end: usize,
}

/// Parse a `${NAME}` / `${NAME:default}` reference starting at `start` (which
/// must index a `$`). `None` if what follows isn't one.
fn parse_reference(src: &str, start: usize) -> Option<Reference<'_>> {
    let bytes = src.as_bytes();
    if !bytes[start..].starts_with(b"${") {
        return None;
    }
    let name_start = start + 2;

    let mut i = name_start;
    while i < bytes.len()
        && (bytes[i].is_ascii_uppercase() || bytes[i] == b'_' || bytes[i].is_ascii_digit())
    {
        i += 1;
    }
    let name = &src[name_start..i];
    if !is_valid_name(name) {
        return None;
    }

    match bytes.get(i) {
        Some(b'}') => Some(Reference {
            name,
            default: None,
            end: i + 1,
        }),
        Some(b':') => {
            let default_start = i + 1;
            // A default may not contain `}` — the first one closes the
            // reference. Anything else (including non-ASCII) is literal.
            let close = bytes[default_start..]
                .iter()
                .position(|b| *b == b'}')
                .map(|off| default_start + off)?;
            Some(Reference {
                name,
                default: Some(&src[default_start..close]),
                end: close + 1,
            })
        }
        // Unterminated, or an illegal character mid-name.
        _ => None,
    }
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vars() -> Vars {
        Vars::from_pairs([("MAILBOX_HOST", "mailbox.dev.overslash.com")])
    }

    fn expand_one(input: &str, vars: &Vars) -> Result<String, Vec<ValidationIssue>> {
        let mut doc = json!({ "url": input });
        expand(&mut doc, vars)?;
        Ok(doc["url"].as_str().unwrap().to_string())
    }

    #[test]
    fn substitutes_a_set_variable() {
        assert_eq!(
            expand_one("https://${MAILBOX_HOST}", &vars()).unwrap(),
            "https://mailbox.dev.overslash.com"
        );
    }

    #[test]
    fn set_variable_wins_over_its_default() {
        assert_eq!(
            expand_one("https://${MAILBOX_HOST:mailbox.overslash.com}", &vars()).unwrap(),
            "https://mailbox.dev.overslash.com"
        );
    }

    #[test]
    fn falls_back_to_the_default_when_unset() {
        assert_eq!(
            expand_one("${METABASE_URL:http://localhost:3033}", &vars()).unwrap(),
            "http://localhost:3033"
        );
    }

    #[test]
    fn empty_default_is_the_empty_string() {
        assert_eq!(expand_one("a${NOPE:}b", &vars()).unwrap(), "ab");
    }

    #[test]
    fn unset_without_a_default_is_an_error_naming_the_env_var() {
        let mut doc = json!({ "servers": [{ "url": "https://${MAILBOX_HOST}" }] });
        let errs = expand(&mut doc, &Vars::empty()).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].code, UNSET_CODE);
        assert_eq!(errs[0].path, "servers.0.url");
        assert!(
            errs[0]
                .message
                .contains("OVERSLASH_TEMPLATE_VAR_MAILBOX_HOST"),
            "message should name the env var to set: {}",
            errs[0].message
        );
    }

    #[test]
    fn reports_every_unresolved_reference_not_just_the_first() {
        let mut doc = json!({ "a": "${ONE}", "b": "${TWO}" });
        let errs = expand(&mut doc, &Vars::empty()).unwrap_err();
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn several_references_in_one_string() {
        let v = Vars::from_pairs([("SCHEME", "https"), ("HOST", "example.com")]);
        assert_eq!(
            expand_one("${SCHEME}://${HOST}/v1?x=${MISSING:1}", &v).unwrap(),
            "https://example.com/v1?x=1"
        );
    }

    #[test]
    fn double_dollar_escapes_a_literal_reference() {
        assert_eq!(
            expand_one("literal $${MAILBOX_HOST}", &vars()).unwrap(),
            "literal ${MAILBOX_HOST}"
        );
    }

    #[test]
    fn leaves_non_references_verbatim() {
        // Lowercase names, jq's `$foo`, a bare `$`, and an unterminated `${`
        // must all survive untouched — templates carry jq expressions and
        // shell-ish prose in descriptions.
        for input in [
            "${lower_case}",
            "${Mixed}",
            "$HOME and $ alone",
            "${UNTERMINATED",
            "cost is $5",
            ".foo | $__loc__",
        ] {
            assert_eq!(expand_one(input, &vars()).unwrap(), input, "input: {input}");
        }
    }

    #[test]
    fn leaves_non_string_values_and_object_keys_alone() {
        let mut doc = json!({
            "${MAILBOX_HOST}": 1,
            "port": 993,
            "enabled": true,
            "nothing": null,
        });
        let before = doc.clone();
        expand(&mut doc, &vars()).unwrap();
        assert_eq!(doc, before);
    }

    #[test]
    fn expands_through_nested_arrays_and_objects() {
        let mut doc = json!({
            "servers": [{ "url": "https://${MAILBOX_HOST}" }],
            "components": { "x": { "y": ["${MAILBOX_HOST}"] } },
        });
        expand(&mut doc, &vars()).unwrap();
        assert_eq!(
            doc["servers"][0]["url"],
            "https://mailbox.dev.overslash.com"
        );
        assert_eq!(doc["components"]["x"]["y"][0], "mailbox.dev.overslash.com");
    }

    #[test]
    fn preserves_multibyte_text_around_a_reference() {
        let v = Vars::from_pairs([("HOST", "hôte.example")]);
        assert_eq!(
            expand_one("Boîte aux lettres — ${HOST} ✉", &v).unwrap(),
            "Boîte aux lettres — hôte.example ✉"
        );
    }

    #[test]
    fn multibyte_default_value() {
        assert_eq!(
            expand_one("${NOPE:café — ✉}", &Vars::empty()).unwrap(),
            "café — ✉"
        );
    }

    #[test]
    fn unresolved_reference_is_left_intact_in_the_output() {
        // Belt and braces: even though the caller sees an Err, a partially
        // expanded document must not read as if the host resolved.
        let mut doc = json!({ "url": "https://${A:ok}/${B}" });
        let _ = expand(&mut doc, &Vars::empty());
        assert_eq!(doc["url"], "https://ok/${B}");
    }

    #[test]
    fn name_validation() {
        assert!(is_valid_name("A"));
        assert!(is_valid_name("MAILBOX_HOST"));
        assert!(is_valid_name("HOST2"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("_LEADING"));
        assert!(!is_valid_name("2LEADING"));
        assert!(!is_valid_name("lower"));
        assert!(!is_valid_name("HAS-DASH"));
    }

    #[test]
    fn from_pairs_round_trips() {
        let v = Vars::from_pairs([("A", "1"), ("B", "2")]);
        assert_eq!(v.len(), 2);
        assert_eq!(v.get("A"), Some("1"));
        assert_eq!(v.iter().collect::<Vec<_>>(), vec![("A", "1"), ("B", "2")]);
        assert!(Vars::empty().is_empty());
    }
}
