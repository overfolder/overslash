//! User-supplied overrides (`key`, `display_name`) and key slugification.

use serde_json::{Map, Value};

use super::{ImportOptions, ImportWarning};

// ── overrides ────────────────────────────────────────────────────────

pub(super) fn apply_overrides(
    root: &mut Map<String, Value>,
    opts: &ImportOptions,
    warnings: &mut Vec<ImportWarning>,
) {
    let info = root
        .entry("info".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(info_obj) = info else {
        return;
    };

    if let Some(dn) = &opts.display_name {
        info_obj.insert("title".to_string(), Value::String(dn.clone()));
    }

    let supplied_key = opts.key.clone();
    if let Some(k) = supplied_key {
        info_obj.insert("x-overslash-key".to_string(), Value::String(k));
        info_obj.remove("key");
    } else if !info_obj.contains_key("x-overslash-key") && !info_obj.contains_key("key") {
        // Derive a best-effort key from the title so the draft has something
        // to call itself. The user can rename before promoting.
        if let Some(title) = info_obj.get("title").and_then(Value::as_str) {
            let derived = slugify(title);
            if !derived.is_empty() {
                info_obj.insert("x-overslash-key".to_string(), Value::String(derived));
                warnings.push(ImportWarning::new(
                    "derived_key",
                    "template key was not declared; derived from info.title",
                    "info.x-overslash-key",
                ));
            }
        }
    }
}

/// Lowercase, keep `[a-z0-9_-]`, replace anything else with `-`, collapse
/// runs, trim leading/trailing `-`. Mirrors the `invalid_key` regex
/// `^[a-z][a-z0-9_-]*$` as closely as a one-shot slugifier can.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
            out.push(c);
            prev_dash = c == '-';
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    // Key must start with [a-z]; if it starts with a digit, prefix with `x-`.
    if let Some(first) = out.chars().next() {
        if !first.is_ascii_lowercase() {
            out.insert_str(0, "x-");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::import::prepare_from_value;
    use crate::openapi::import::tests::base_doc;

    #[test]
    fn derives_key_from_title() {
        let prep = prepare_from_value(base_doc(), &ImportOptions::default());
        let key = prep.doc["info"]["x-overslash-key"].as_str().unwrap();
        assert_eq!(key, "widgets");
        assert!(prep.warnings.iter().any(|w| w.code == "derived_key"));
    }

    #[test]
    fn explicit_key_override_wins() {
        let opts = ImportOptions {
            key: Some("my-widgets".into()),
            ..Default::default()
        };
        let prep = prepare_from_value(base_doc(), &opts);
        assert_eq!(
            prep.doc["info"]["x-overslash-key"].as_str().unwrap(),
            "my-widgets"
        );
    }

    #[test]
    fn display_name_override_updates_title() {
        let opts = ImportOptions {
            display_name: Some("Widget Service".into()),
            ..Default::default()
        };
        let prep = prepare_from_value(base_doc(), &opts);
        assert_eq!(
            prep.doc["info"]["title"].as_str().unwrap(),
            "Widget Service"
        );
    }

    #[test]
    fn slugify_produces_valid_keys() {
        assert_eq!(slugify("Google Calendar"), "google-calendar");
        assert_eq!(slugify("  My  Cool  API!!  "), "my-cool-api");
        assert_eq!(slugify("1password"), "x-1password");
    }

    #[test]
    fn slugify_handles_leading_digit_and_punctuation() {
        // Leading digit gets an `x-` prefix so the key matches `^[a-z]...`.
        assert_eq!(slugify("3D Widgets"), "x-3d-widgets");
        // All-punctuation input collapses to empty, no panic.
        assert_eq!(slugify("!!! ??? !!!"), "");
        // Underscores and hyphens are preserved as-is.
        assert_eq!(slugify("my_cool-api"), "my_cool-api");
    }
}
