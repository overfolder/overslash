use super::key::DerivedKey;

/// Parse a flat permission key string into its structured components.
/// Format: `{service}:{action}:{arg}` where arg may contain colons, and may
/// itself be `{label}={value}`.
pub fn parse_derived_key(key: &str) -> DerivedKey {
    let mut parts = key.splitn(3, ':');
    let service = parts.next().unwrap_or("").to_string();
    let action = parts.next().unwrap_or("").to_string();
    let arg = parts.next().unwrap_or("*").to_string();
    let (label, value) = split_scope_arg(&arg);
    DerivedKey {
        key: key.to_string(),
        service,
        action,
        arg,
        label,
        value,
    }
}

/// Split a `{label}={value}` arg. The prefix only counts as a label when it is
/// a bare identifier, so a value that itself contains `=` (a query string, a
/// base64 pad) is returned whole rather than sliced at an arbitrary `=`.
fn split_scope_arg(arg: &str) -> (Option<String>, String) {
    match arg.split_once('=') {
        Some((label, value)) if crate::types::is_scope_ident(label) => {
            (Some(label.to_string()), value.to_string())
        }
        _ => (None, arg.to_string()),
    }
}

/// The strings a rule may be matched against for one key.
///
/// A labelled key also answers to its **value-only** form, so a rule written
/// before labels existed — or written deliberately label-agnostic, like
/// `email:send:*@example.com` — still covers it no matter which param carried
/// the value. A `label=`-qualified rule only matches keys with that label,
/// which is what makes `email:send:cc=*@example.com` narrower than the bare
/// form rather than a synonym for it.
fn match_forms(key: &str) -> Vec<String> {
    let dk = parse_derived_key(key);
    match dk.label {
        Some(_) => vec![
            key.to_string(),
            format!("{}:{}:{}", dk.service, dk.action, dk.value),
        ],
        None => vec![key.to_string()],
    }
}

/// Does `pattern` cover `key`, in either of the key's [`match_forms`]?
pub(crate) fn rule_matches(pattern: &str, key: &str) -> bool {
    match_forms(key)
        .iter()
        .any(|form| glob_match::glob_match(pattern, form))
}

/// Does the permission key `pattern` cover the concrete key `key`?
///
/// Same glob + [`match_forms`] semantics the rule engine uses, exposed for
/// callers that need to validate a hand-typed key against what a request
/// actually asked for (e.g. an approval's "Custom…" remember key) without
/// synthesizing a `PermissionRule`.
pub fn key_covers(pattern: &str, key: &str) -> bool {
    rule_matches(pattern, key)
}

/// Parse all permission key strings into structured `DerivedKey`s.
pub fn derive_keys(permission_keys: &[String]) -> Vec<DerivedKey> {
    permission_keys
        .iter()
        .map(|k| parse_derived_key(k))
        .collect()
}

/// Compute the broadening ladder for a single derived key.
/// Returns a list of progressively broader key strings (including the original).
pub(crate) fn broadening_ladder(dk: &DerivedKey) -> Vec<String> {
    let mut ladder = vec![dk.key.clone()];

    match dk.service.as_str() {
        "http" => {
            // http:{METHOD}:{host}{path} → http:{METHOD}:{host}/** → http:ANY:{host}/**
            let host = dk.arg.split('/').next().unwrap_or(&dk.arg);
            let host_wildcard = format!("http:{}:{host}/**", dk.action);
            if host_wildcard != dk.key {
                ladder.push(host_wildcard);
            }
            if dk.action != "ANY" {
                ladder.push(format!("http:ANY:{host}/**"));
            }
        }
        "secret" => {
            // secret:{name}:{target} → secret:{name}:*
            if dk.arg != "*" {
                ladder.push(format!("secret:{}:*", dk.action));
            }
        }
        _ => {
            // Service-HTTP keys (`{service}:{METHOD}:{path}`) carry a path
            // in `arg` starting with `/`. Path globs need `/**` because
            // `*` does not span `/` in `glob_match`. Detect and emit the
            // path-aware ladder.
            if dk.arg.starts_with('/') {
                // {service}:{METHOD}:{path} → {service}:{METHOD}:/** → {service}:*:/**
                let method_wildcard = format!("{}:{}:/**", dk.service, dk.action);
                if method_wildcard != dk.key {
                    ladder.push(method_wildcard);
                }
                ladder.push(format!("{}:*:/**", dk.service));
            } else if dk.label.is_some() && dk.value.contains('/') {
                // Slash-carrying labelled keys — the D42 table shape
                // ({service}:{action}:table={db}/{relation}). `*` does not
                // span `/`, so the classic `:*` / `:*:*` rungs would suggest
                // rules that match nothing; the ladder widens value-only →
                // db-wide → `**` forms instead:
                //   table=prod/public.orders → prod/public.orders (any label)
                //   → table=prod/* (whole DB) → {service}:{action}:**
                //   → {service}:**
                ladder.push(format!("{}:{}:{}", dk.service, dk.action, dk.value));
                if let Some((db, rest)) = dk.value.split_once('/') {
                    if rest != "*"
                        && let Some(label) = &dk.label
                    {
                        ladder.push(format!("{}:{}:{label}={db}/*", dk.service, dk.action));
                    }
                }
                ladder.push(format!("{}:{}:**", dk.service, dk.action));
                ladder.push(format!("{}:**", dk.service));
            } else {
                // Service action:
                // {service}:{action}:{label}={value} → {service}:{action}:{value}
                //   → {service}:{action}:* → {service}:*:*
                //
                // The value-only rung is a real widening step, not cosmetics:
                // it grants the same correspondent/resource under *any* label,
                // which for `email:send` is "this address, whichever header it
                // is on". Unlabelled args skip it.
                if dk.label.is_some() {
                    ladder.push(format!("{}:{}:{}", dk.service, dk.action, dk.value));
                }
                if dk.arg != "*" {
                    ladder.push(format!("{}:{}:*", dk.service, dk.action));
                }
                ladder.push(format!("{}:*:*", dk.service));
            }
        }
    }

    ladder
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `=` inside a *value* must not be mistaken for a label separator — the
    /// prefix only counts when it is a bare identifier.
    #[test]
    fn a_non_identifier_prefix_is_not_a_label() {
        let dk = parse_derived_key("http:GET:api.example.com/x?a=1");
        assert_eq!(dk.label, None);
        assert_eq!(dk.value, "api.example.com/x?a=1");
        assert_eq!(match_forms(&dk.key), vec!["http:GET:api.example.com/x?a=1"]);
    }

    #[test]
    fn parse_derived_key_splits_the_label() {
        let dk = parse_derived_key("email:send:recipient=jane@example.com");
        assert_eq!(dk.service, "email");
        assert_eq!(dk.action, "send");
        assert_eq!(dk.arg, "recipient=jane@example.com");
        assert_eq!(dk.label.as_deref(), Some("recipient"));
        assert_eq!(dk.value, "jane@example.com");
    }

    /// The ladder gains one rung for a labelled key: the same value under any
    /// label ("this correspondent, whichever header").
    #[test]
    fn broadening_ladder_offers_the_value_only_rung() {
        let dk = parse_derived_key("email:send:recipient=jane@example.com");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "email:send:recipient=jane@example.com",
                "email:send:jane@example.com",
                "email:send:*",
                "email:*:*"
            ]
        );
    }

    #[test]
    fn broadening_ladder_unchanged_for_unlabelled_args() {
        let dk = parse_derived_key("github:create_pull_request:overfolder/backend");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "github:create_pull_request:overfolder/backend",
                "github:create_pull_request:*",
                "github:*:*"
            ]
        );
    }

    #[test]
    fn broadening_ladder_for_service_http_uses_globstar() {
        let dk = parse_derived_key("github:POST:/repos/x/pulls");
        let ladder = broadening_ladder(&dk);
        assert_eq!(
            ladder,
            vec![
                "github:POST:/repos/x/pulls".to_string(),
                "github:POST:/**".to_string(),
                "github:*:/**".to_string(),
            ]
        );
    }

    /// SPEC §5: the `http` pseudo-service ladder must NEVER suggest
    /// `http:*:*` or `http:VERB:*` — only host-scoped wildcards
    /// (`http:VERB:host/**` and `http:ANY:host/**`).
    #[test]
    fn broadening_ladder_for_http_never_emits_unscoped_wildcards() {
        let dk = parse_derived_key("http:POST:api.github.com/v3/repos");
        let ladder = broadening_ladder(&dk);
        assert_eq!(
            ladder,
            vec![
                "http:POST:api.github.com/v3/repos".to_string(),
                "http:POST:api.github.com/**".to_string(),
                "http:ANY:api.github.com/**".to_string(),
            ]
        );
        for rung in &ladder {
            assert!(
                !rung.starts_with("http:*:") && !rung.ends_with(":*"),
                "ladder must not suggest unbounded http wildcards (got {rung:?})"
            );
        }
    }

    // ── DerivedKey / SuggestedTier tests ───────────────────────────────

    #[test]
    fn parse_service_action_key() {
        let dk = parse_derived_key("github:create_pull_request:overfolder/backend");
        assert_eq!(dk.service, "github");
        assert_eq!(dk.action, "create_pull_request");
        assert_eq!(dk.arg, "overfolder/backend");
    }

    #[test]
    fn parse_http_key() {
        let dk = parse_derived_key("http:POST:api.github.com/repos/x/pulls");
        assert_eq!(dk.service, "http");
        assert_eq!(dk.action, "POST");
        assert_eq!(dk.arg, "api.github.com/repos/x/pulls");
    }

    #[test]
    fn parse_key_with_star_arg() {
        let dk = parse_derived_key("github:list_repos:*");
        assert_eq!(dk.arg, "*");
    }

    #[test]
    fn parse_key_missing_arg_defaults_to_star() {
        let dk = parse_derived_key("github:list_repos");
        assert_eq!(dk.arg, "*");
    }

    #[test]
    fn key_covers_label_stripped_form() {
        assert!(key_covers(
            "email:send:*",
            "email:send:recipient=ada@example.com"
        ));
        assert!(key_covers(
            "email:send:recipient=ada@example.com",
            "email:send:recipient=ada@example.com"
        ));
        assert!(!key_covers(
            "email:send:recipient=bob@example.com",
            "email:send:recipient=ada@example.com"
        ));
        assert!(!key_covers("github:*:*", "email:send:recipient=ada@x.com"));
    }

    /// The glob truths D42's rule surface depends on. `*` does not span `/`,
    /// `**` does, `*` spans `.`.
    #[test]
    fn sql_table_key_cover_truths() {
        let key = "metabase:run_query:table=reveni-prod/public.orders";
        for (pattern, covers) in [
            ("metabase:run_query:table=reveni-prod/public.orders", true),
            ("metabase:run_query:table=reveni-prod/*", true), // whole DB
            ("metabase:run_query:table=reveni-prod/public.*", true), // schema
            ("metabase:run_query:table=*/public.orders", true), // any DB
            ("metabase:run_query:reveni-prod/public.orders", true), // value-only form
            ("metabase:run_query:*", false),                  // `*` does not span `/`
            ("metabase:run_query:**", true),
            ("metabase:**", true),
            // Qualified rule does not cover an unqualified relation.
            ("metabase:run_query:table=reveni-prod/public.orders", true),
        ] {
            assert_eq!(key_covers(pattern, key), covers, "{pattern} vs {key}");
        }
        // …and the unqualified relation is its own key.
        assert!(!key_covers(
            "metabase:run_query:table=reveni-prod/public.orders",
            "metabase:run_query:table=reveni-prod/orders"
        ));
        // The sentinel is only covered by the db-wide-mut (or broader) grants.
        let sentinel = "metabase:run_query:table_mut=reveni-prod/*";
        assert!(key_covers(
            "metabase:run_query:table_mut=reveni-prod/*",
            sentinel
        ));
        assert!(!key_covers(
            "metabase:run_query:table_mut=reveni-prod/public.orders",
            sentinel
        ));
    }

    #[test]
    fn sql_table_key_ladder_uses_globstar_rungs() {
        let dk = parse_derived_key("metabase:run_query:table=reveni-prod/public.orders");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "metabase:run_query:table=reveni-prod/public.orders",
                "metabase:run_query:reveni-prod/public.orders",
                "metabase:run_query:table=reveni-prod/*",
                "metabase:run_query:**",
                "metabase:**",
            ]
        );
        // A mut key ladders identically within its own label, with the
        // value-only rung as the read-or-write middle step.
        let dk = parse_derived_key("metabase:run_query:table_mut=reveni-prod/public.orders");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "metabase:run_query:table_mut=reveni-prod/public.orders",
                "metabase:run_query:reveni-prod/public.orders",
                "metabase:run_query:table_mut=reveni-prod/*",
                "metabase:run_query:**",
                "metabase:**",
            ]
        );

        // The sentinel skips the db-wide rung (it *is* the db-wide shape).
        let dk = parse_derived_key("metabase:run_query:table_mut=reveni-prod/*");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "metabase:run_query:table_mut=reveni-prod/*",
                "metabase:run_query:reveni-prod/*",
                "metabase:run_query:**",
                "metabase:**",
            ]
        );
    }

    /// Regression: slash-free labelled keys (email's `recipient=`) keep the
    /// classic ladder untouched.
    #[test]
    fn slash_free_ladder_unchanged() {
        let dk = parse_derived_key("email:send:recipient=a@example.com");
        assert_eq!(
            broadening_ladder(&dk),
            vec![
                "email:send:recipient=a@example.com",
                "email:send:a@example.com",
                "email:send:*",
                "email:*:*",
            ]
        );
    }
}
