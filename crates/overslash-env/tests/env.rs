//! Tests for the env accessors.
//!
//! An integration test rather than a `#[cfg(test)]` module because setting a
//! variable is `unsafe` under edition 2024 and the library forbids unsafe code.
//! Testing through the public API is the right shape for this crate anyway.
//!
//! **Every test uses a variable name no other test touches.** The process
//! environment is global and the test runner is threaded, so shared names are
//! the standard way these suites turn flaky; unique names make a lock
//! unnecessary rather than merely unlikely to be needed.

use overslash_env as env;

fn set(name: &str, value: &str) {
    // SAFETY: single-threaded with respect to this variable — each test owns a
    // name no other test reads or writes.
    unsafe { std::env::set_var(name, value) };
}

fn clear(name: &str) {
    // SAFETY: as above.
    unsafe { std::env::remove_var(name) };
}

// ── the rule: empty means unset ─────────────────────────────────────────────

#[test]
fn optional_treats_unset_empty_and_whitespace_alike() {
    clear("OVS_TEST_OPTIONAL");
    assert_eq!(env::optional("OVS_TEST_OPTIONAL"), None, "unset");

    set("OVS_TEST_OPTIONAL", "");
    assert_eq!(env::optional("OVS_TEST_OPTIONAL"), None, "empty");

    set("OVS_TEST_OPTIONAL", "   \t\n ");
    assert_eq!(env::optional("OVS_TEST_OPTIONAL"), None, "whitespace-only");

    set("OVS_TEST_OPTIONAL", "value");
    assert_eq!(
        env::optional("OVS_TEST_OPTIONAL"),
        Some("value".to_string())
    );
}

#[test]
fn values_are_trimmed() {
    // Secret Manager payloads populated from shell pipelines routinely pick up
    // a trailing newline; a key that differs from the real one by `\n` fails
    // in a way that looks nothing like whitespace.
    set("OVS_TEST_TRIM", "  hunter2\n");
    assert_eq!(env::optional("OVS_TEST_TRIM"), Some("hunter2".to_string()));
    assert_eq!(env::or_default("OVS_TEST_TRIM", "x"), "hunter2");
    assert_eq!(env::required("OVS_TEST_TRIM").unwrap(), "hunter2");
}

#[test]
fn required_reports_the_name_for_unset_and_for_empty() {
    clear("OVS_TEST_REQUIRED");
    let err = env::required("OVS_TEST_REQUIRED").unwrap_err();
    assert_eq!(err.name(), "OVS_TEST_REQUIRED");
    assert!(err.to_string().contains("OVS_TEST_REQUIRED"));

    // The case this whole crate exists for: present, and useless.
    set("OVS_TEST_REQUIRED", "");
    assert_eq!(
        env::required("OVS_TEST_REQUIRED").unwrap_err().name(),
        "OVS_TEST_REQUIRED",
        "an empty required var must read as missing, not as configured"
    );

    set("OVS_TEST_REQUIRED", "here");
    assert_eq!(env::required("OVS_TEST_REQUIRED").unwrap(), "here");
}

#[test]
fn is_set_follows_the_same_rule() {
    clear("OVS_TEST_IS_SET");
    assert!(!env::is_set("OVS_TEST_IS_SET"));
    set("OVS_TEST_IS_SET", "");
    assert!(!env::is_set("OVS_TEST_IS_SET"));
    set("OVS_TEST_IS_SET", "yes");
    assert!(env::is_set("OVS_TEST_IS_SET"));
}

#[test]
fn or_default_does_not_let_empty_beat_the_default() {
    clear("OVS_TEST_DEFAULT");
    assert_eq!(
        env::or_default("OVS_TEST_DEFAULT", "127.0.0.1"),
        "127.0.0.1"
    );
    set("OVS_TEST_DEFAULT", "");
    assert_eq!(
        env::or_default("OVS_TEST_DEFAULT", "127.0.0.1"),
        "127.0.0.1",
        "empty must fall back, not bind to \":3000\""
    );
    set("OVS_TEST_DEFAULT", "0.0.0.0");
    assert_eq!(env::or_default("OVS_TEST_DEFAULT", "127.0.0.1"), "0.0.0.0");
}

// ── parsing ─────────────────────────────────────────────────────────────────

#[test]
fn parse_opt_returns_none_for_unset_empty_and_unparseable() {
    clear("OVS_TEST_PARSE");
    assert_eq!(env::parse_opt::<u64>("OVS_TEST_PARSE"), None);
    set("OVS_TEST_PARSE", "");
    assert_eq!(env::parse_opt::<u64>("OVS_TEST_PARSE"), None);
    set("OVS_TEST_PARSE", "3o000");
    assert_eq!(env::parse_opt::<u64>("OVS_TEST_PARSE"), None, "typo");
    set("OVS_TEST_PARSE", " 30000 ");
    assert_eq!(env::parse_opt::<u64>("OVS_TEST_PARSE"), Some(30_000));
}

#[test]
fn parse_or_die_defaults_when_unset_or_empty() {
    clear("OVS_TEST_DIE_OK");
    assert_eq!(env::parse_or_die::<u8>("OVS_TEST_DIE_OK", 1), 1);
    set("OVS_TEST_DIE_OK", "");
    assert_eq!(env::parse_or_die::<u8>("OVS_TEST_DIE_OK", 1), 1);
    set("OVS_TEST_DIE_OK", "7");
    assert_eq!(env::parse_or_die::<u8>("OVS_TEST_DIE_OK", 1), 7);
}

#[test]
#[should_panic(expected = "OVS_TEST_DIE_BAD")]
fn parse_or_die_panics_on_an_unparseable_value() {
    // Out of range for u8. Folding this back to the default is the failure
    // mode the helper exists to prevent.
    set("OVS_TEST_DIE_BAD", "256");
    let _ = env::parse_or_die::<u8>("OVS_TEST_DIE_BAD", 1);
}

// ── flags ───────────────────────────────────────────────────────────────────

#[test]
fn flag_accepts_every_documented_truthy_spelling() {
    for v in ["true", "1", "yes", "on", "TRUE", "Yes", "ON"] {
        set("OVS_TEST_FLAG_ON", v);
        assert!(env::flag("OVS_TEST_FLAG_ON"), "{v:?} should be truthy");
    }
}

#[test]
fn flag_accepts_every_documented_falsey_spelling() {
    for v in ["false", "0", "no", "off", "FALSE", "No", "OFF"] {
        set("OVS_TEST_FLAG_OFF", v);
        assert!(!env::flag("OVS_TEST_FLAG_OFF"), "{v:?} should be falsey");
    }
}

#[test]
fn flag_is_off_when_unset_or_empty() {
    clear("OVS_TEST_FLAG_UNSET");
    assert!(!env::flag("OVS_TEST_FLAG_UNSET"));
    set("OVS_TEST_FLAG_UNSET", "");
    assert!(
        !env::flag("OVS_TEST_FLAG_UNSET"),
        "DEV_AUTH=\"\" must not enable a bypass"
    );
    set("OVS_TEST_FLAG_UNSET", "   ");
    assert!(!env::flag("OVS_TEST_FLAG_UNSET"));
}

#[test]
fn an_unrecognised_value_falls_back_to_the_declared_default() {
    // Not to `false`: a security gate declares `false` and stays closed, while
    // a default-on flag declares `true` and is not silently switched off by a
    // typo. Both get a warning.
    set("OVS_TEST_FLAG_JUNK", "maybe");
    assert!(!env::flag_or("OVS_TEST_FLAG_JUNK", false));
    assert!(env::flag_or("OVS_TEST_FLAG_JUNK", true));
}

#[test]
fn flag_or_respects_an_explicit_falsey_value_over_an_on_default() {
    set("OVS_TEST_FLAG_DEFAULT_ON", "0");
    assert!(
        !env::flag_or("OVS_TEST_FLAG_DEFAULT_ON", true),
        "an explicit 0 must disable a default-on flag"
    );
    clear("OVS_TEST_FLAG_DEFAULT_ON");
    assert!(env::flag_or("OVS_TEST_FLAG_DEFAULT_ON", true));
}

// ── lists ───────────────────────────────────────────────────────────────────

#[test]
fn list_drops_blank_entries_and_trims() {
    set("OVS_TEST_LIST", " ,a.example.com, ,b.example.com,");
    assert_eq!(
        env::list("OVS_TEST_LIST"),
        vec!["a.example.com".to_string(), "b.example.com".to_string()]
    );
}

#[test]
fn list_is_empty_for_unset_empty_and_commas_only() {
    clear("OVS_TEST_LIST_EMPTY");
    assert!(env::list("OVS_TEST_LIST_EMPTY").is_empty());
    set("OVS_TEST_LIST_EMPTY", "");
    assert!(env::list("OVS_TEST_LIST_EMPTY").is_empty());
    set("OVS_TEST_LIST_EMPTY", ",,,");
    assert!(
        env::list("OVS_TEST_LIST_EMPTY").is_empty(),
        "an allow-list must never contain an empty entry"
    );
}
