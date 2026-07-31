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
//! - `${NAME?}` — **defaults to null**: unset replaces the whole value with
//!   JSON `null` rather than erroring. For a `servers[].url` that means
//!   `extract_hosts` skips the entry and the template compiles with no host,
//!   which is already the established "the operator supplies the endpoint when
//!   they create the instance" shape (`telegram`, `whatsapp`, every MCP
//!   template). So a self-hosted service like Metabase needs no default *and*
//!   does not vanish when the deployment sets nothing — it just asks at
//!   instantiation. Must be the entire value; see [`OPTIONAL_PARTIAL_CODE`].
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

/// [`ValidationIssue::code`] for a `${NAME?}` that is not the entire value.
///
/// Nulling a value is an all-or-nothing edit, so `"https://${HOST?}/v1"` has no
/// sensible answer: keeping `https:///v1` is a broken URL and discarding the
/// literal text silently throws away part of what the author wrote. Rejecting
/// at compile time costs the author one edit and removes the guesswork.
pub const OPTIONAL_PARTIAL_CODE: &str = "template_var_optional_not_whole";

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
            match expand_str(s, vars, path, errors) {
                Expanded::Unchanged => {}
                Expanded::Text(t) => *s = t,
                Expanded::Null => *node = Value::Null,
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

/// Outcome of expanding one string value.
enum Expanded {
    /// No reference and no escape — the caller keeps the original allocation.
    Unchanged,
    Text(String),
    /// An unset `${NAME?}`: the value becomes JSON `null`.
    Null,
}

/// Expand one string.
///
/// Byte indexing is safe throughout: every delimiter this scans for (`$`, `{`,
/// `}`, `:`, `?`) is ASCII, and an ASCII byte can never occur inside a
/// multi-byte UTF-8 sequence — so a match is always on a character boundary
/// even when the surrounding text (or a default value) is not ASCII.
fn expand_str(src: &str, vars: &Vars, path: &str, errors: &mut Vec<ValidationIssue>) -> Expanded {
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
            Some(Reference {
                name,
                fallback,
                end,
            }) => {
                match vars.get(name) {
                    Some(value) => out.push_str(value),
                    None => match fallback {
                        Fallback::Text(d) => out.push_str(d),
                        Fallback::Null => {
                            // All-or-nothing: nulling a value that also carries
                            // literal text has no honest answer, so the author
                            // is told rather than guessed at.
                            if i != 0 || end != bytes.len() {
                                errors.push(ValidationIssue::new(
                                    OPTIONAL_PARTIAL_CODE,
                                    format!(
                                        "`${{{name}?}}` defaults to null, so it must be the \
                                         entire value — it cannot be combined with other text. \
                                         Move the surrounding text into `{ENV_PREFIX}{name}`, or \
                                         give the reference a default instead."
                                    ),
                                    path,
                                ));
                                out.push_str(&src[i..end]);
                                i = end;
                                changed = true;
                                continue;
                            }
                            return Expanded::Null;
                        }
                        Fallback::NoFallback => {
                            errors.push(ValidationIssue::new(
                                UNSET_CODE,
                                format!(
                                    "template variable `{name}` is not set and declares no \
                                     default; set `{ENV_PREFIX}{name}` on this deployment, or \
                                     write `${{{name}:<default>}}` — or `${{{name}?}}` to leave \
                                     it unset and have the value supplied per instance"
                                ),
                                path,
                            ));
                            // Keep the reference verbatim so a partially-expanded
                            // string never reaches a caller as if it had resolved.
                            out.push_str(&src[i..end]);
                        }
                    },
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

    if changed {
        Expanded::Text(out)
    } else {
        Expanded::Unchanged
    }
}

/// What a reference resolves to when the variable is unset.
///
/// `NoFallback` rather than `None`: this enum is matched right next to
/// `Option`s of the same values, and two `None`s in one `match` is a needless
/// re-reading. Worth the redundant-sounding name, hence the lint suppression.
#[allow(clippy::enum_variant_names)]
enum Fallback<'a> {
    /// `${NAME}` — an error.
    NoFallback,
    /// `${NAME:default}`.
    Text(&'a str),
    /// `${NAME?}` — JSON `null`.
    Null,
}

struct Reference<'a> {
    name: &'a str,
    fallback: Fallback<'a>,
    /// Byte index just past the closing `}`.
    end: usize,
}

/// Parse a `${NAME}` / `${NAME:default}` / `${NAME?}` reference starting at
/// `start` (which must index a `$`). `None` if what follows isn't one.
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
            fallback: Fallback::NoFallback,
            end: i + 1,
        }),
        // `${NAME?}` — the `?` must be the last thing before `}`, so a stray
        // `${NAME?x}` is left verbatim rather than silently read as optional.
        Some(b'?') if bytes.get(i + 1) == Some(&b'}') => Some(Reference {
            name,
            fallback: Fallback::Null,
            end: i + 2,
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
                fallback: Fallback::Text(&src[default_start..close]),
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

    /// Expand a whole value, keeping its JSON type — `expand_one` asserts the
    /// result is a string, which the `?` mode deliberately isn't.
    fn expand_value(input: &str, vars: &Vars) -> Result<Value, Vec<ValidationIssue>> {
        let mut doc = json!({ "url": input });
        expand(&mut doc, vars)?;
        Ok(doc["url"].clone())
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
    fn optional_reference_resolves_to_null_when_unset() {
        // The point of `?`: a self-hosted service whose URL this deployment
        // does not know must still ship a usable template — the operator is
        // asked for the endpoint when they create the instance.
        assert_eq!(
            expand_value("${METABASE_URL?}", &Vars::empty()).unwrap(),
            Value::Null
        );
    }

    #[test]
    fn optional_reference_still_prefers_a_set_value() {
        let v = Vars::from_pairs([("METABASE_URL", "https://mb.example.com")]);
        assert_eq!(
            expand_value("${METABASE_URL?}", &v).unwrap(),
            json!("https://mb.example.com")
        );
    }

    #[test]
    fn a_null_server_url_leaves_no_host() {
        // The property the metabase template relies on: `extract_hosts` skips a
        // `servers` entry whose `url` is not a string, so an unset optional
        // reference compiles to a template with no host rather than a broken
        // one — which is the existing "operator supplies the endpoint at
        // instantiation" shape.
        let mut doc = json!({ "servers": [{ "url": "${METABASE_URL?}" }] });
        expand(&mut doc, &Vars::empty()).unwrap();
        assert_eq!(doc["servers"][0]["url"], Value::Null);
    }

    #[test]
    fn optional_reference_must_be_the_entire_value() {
        // `https://${HOST?}` has no honest answer when HOST is unset: keeping
        // `https://` is a broken URL and dropping it silently discards what the
        // author wrote. Rejected rather than guessed.
        let errs = expand_value("https://${HOST?}", &Vars::empty()).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].code, OPTIONAL_PARTIAL_CODE);

        // Set is fine either way — the restriction is about the unset case
        // being a type change, so it applies uniformly rather than depending on
        // the deployment's configuration.
        let v = Vars::from_pairs([("HOST", "h.example")]);
        let errs = expand_value("https://${HOST?}", &v);
        assert_eq!(errs.unwrap(), json!("https://h.example"));
    }

    #[test]
    fn question_mark_is_only_special_immediately_before_the_brace() {
        // `${NAME?x}` is not a reference at all — left verbatim rather than
        // silently read as optional-with-junk.
        assert_eq!(
            expand_one("${HOST?x}", &Vars::empty()).unwrap(),
            "${HOST?x}"
        );
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
