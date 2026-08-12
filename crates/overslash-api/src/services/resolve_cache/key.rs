//! Cache-key derivation and the TTL rule.
//!
//! Both are security-relevant enough to be worth reading on their own: the key
//! is what keeps one principal's resolutions out of another's, and the TTL is
//! how long a permission grant may be matched against a stale mapping.

use std::time::Duration;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::Config;

// ── Key derivation ──────────────────────────────────────────────────

/// Everything about *who is asking* and *what they're asking through*. Held
/// separately from the per-resolver target so the expensive-to-assemble half is
/// built once per call.
#[derive(Debug, Clone)]
pub struct CacheScope {
    pub org_id: Uuid,
    /// Owner identity (D22). Connections resolve at the owner, so sibling
    /// agents under one owner share a credential and *should* share an entry.
    /// The caller's own identity is deliberately absent: two identities with
    /// different resolvers already land on different keys, because the
    /// projection and target are both in the preimage.
    pub ceiling_user_id: Uuid,
    pub instance_id: Option<Uuid>,
    /// Which credential this resolves through. **Load-bearing**: gmail's
    /// `userId: me` produces a byte-identical URL for every user on earth, so a
    /// key without this would serve one person's address to another.
    ///
    /// Never a token — a rotating bearer would kill the hit rate on exactly the
    /// long-lived case, and a hash of one sitting in a shared store is an
    /// offline confirmation oracle. Connection id, account email, provider, or
    /// vault *reference* names only.
    pub credential_fingerprint: String,
    pub service_key: String,
    /// `http` or `mcp`.
    pub runtime: &'static str,
    pub namespace: Option<String>,
}

// ── Credential fingerprints ─────────────────────────────────────────

/// Name the credential an HTTP resolver GET will authenticate with.
///
/// This is the field that keeps one tenant's resolutions out of another's, and
/// one *user's* out of another's inside a tenant. gmail's `userId: me` produces
/// a byte-identical URL for every user on earth, so without this the first
/// caller's address would be served to the second.
///
/// Never the credential itself. `principal` is the OAuth connection's account
/// email; `secrets` contributes vault *references*, which are pointers, not
/// values. A bearer token would be wrong twice over: it rotates hourly, which
/// would miss on exactly the long-lived lookups worth caching, and a hash of a
/// live token in a shared store is an offline confirmation oracle.
///
/// The `secrets` arm also covers a case OAuth does not: a Mode B/C call passing
/// explicit `req.secrets` resolves with no principal and no connection, so two
/// agents under one owner using *different* secret names would otherwise
/// collide on one entry.
///
/// Takes the three fields rather than `ResolvedAuth` so this stays testable and
/// so a service module does not reach back into a route module for a type.
pub fn http_credential_fingerprint(
    principal: Option<&str>,
    secrets: &[overslash_core::types::SecretRef],
    authenticated: bool,
) -> String {
    if let Some(principal) = principal {
        return format!("acct:{principal}");
    }
    if !secrets.is_empty() {
        // `vault_names` resolves credential-slot bindings to the actual vault
        // keys, which is what decides *whose* credential this is. The slot name
        // rides along so two slots bound to the same secret stay distinct.
        let mut refs: Vec<String> = secrets
            .iter()
            .map(|s| format!("{}={}", s.name, s.vault_names().join("+")))
            .collect();
        refs.sort();
        return format!("vault:{}", refs.join(","));
    }
    // An OAuth header with no principal recorded, or genuinely unauthenticated.
    // Sharing one entry across every anonymous caller of a URL is right;
    // sharing one across OAuth callers whose account we failed to name is not.
    if authenticated {
        return "oauth:unnamed".to_string();
    }
    "anon".to_string()
}

/// Name the credential an MCP resolver `tools/call` will authenticate with.
///
/// Same job as [`http_credential_fingerprint`], different inputs: OAuth names
/// the connection the bearer was minted from, `Bearer` names the vault secret
/// the instance resolved. Two instances of one template pointed at two
/// different containers must never share an entry, and neither must two owners
/// on the same instance.
pub fn mcp_credential_fingerprint(
    connection_id: Option<Uuid>,
    auth: &overslash_core::types::McpAuth,
) -> String {
    use overslash_core::types::McpAuth;
    match (connection_id, auth) {
        (Some(id), _) => format!("conn:{id}"),
        (None, McpAuth::Bearer { secret_name }) => {
            format!("vault:{}", secret_name.as_deref().unwrap_or("-"))
        }
        (None, McpAuth::OAuth { provider, .. }) => format!("oauth:{provider}"),
        (None, McpAuth::None) => "anon".to_string(),
    }
}

/// Length-prefix each field rather than joining on a delimiter. A field that
/// can contain the delimiter — an org-authored service key, an instance name —
/// could otherwise shift the boundaries and forge a collision.
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
    buf.extend_from_slice(field);
}

impl CacheScope {
    /// `osr:v1:{namespace}:{org_id}:{sha256 hex}`
    ///
    /// - `osr:` because the API and the public URL shortener share one Valkey
    ///   instance (`infra/main.tf`), and `oversla-sh` already owns `sh:`.
    /// - `v1` so a preimage or value-shape change cannot collide with entries
    ///   written by the other half of a rolling deploy.
    /// - `org_id` in plaintext, and nothing else: it lets a future `SCAN` serve
    ///   an org-level purge, and it means a preimage bug degrades to a miss
    ///   *within* a tenant rather than across tenants.
    pub(super) fn key(&self, target: &str, display: Option<&str>, scope: Option<&str>) -> String {
        let mut buf = Vec::with_capacity(256);
        push_field(&mut buf, b"osr/v1");
        push_field(&mut buf, self.org_id.as_bytes());
        push_field(&mut buf, self.ceiling_user_id.as_bytes());
        match self.instance_id {
            Some(id) => push_field(&mut buf, id.as_bytes()),
            None => push_field(&mut buf, b"-"),
        }
        push_field(&mut buf, self.credential_fingerprint.as_bytes());
        push_field(&mut buf, self.service_key.as_bytes());
        push_field(&mut buf, self.runtime.as_bytes());
        push_field(&mut buf, target.as_bytes());
        push_field(&mut buf, display.unwrap_or("-").as_bytes());
        push_field(&mut buf, scope.unwrap_or("-").as_bytes());

        let digest = hex::encode(Sha256::digest(&buf));
        let ns = self.namespace.as_deref().unwrap_or("");
        format!("osr:v1:{ns}:{}:{digest}", self.org_id)
    }
}

/// The MCP half of a resolver's target. `resolved_url` is in here because
/// `tool + args` says nothing about *which server* — two instances of one
/// template can point at two different containers.
pub fn mcp_target(resolved_url: &str, tool: &str, args: &serde_json::Value) -> String {
    // `serde_json::Value::Object` is a BTreeMap in our build, so this is
    // already ordered; serialising explicitly rather than relying on that.
    let canonical = serde_json::to_string(args).unwrap_or_default();
    format!("{resolved_url}\u{0}{tool}\u{0}{canonical}")
}

// ── TTL resolution ──────────────────────────────────────────────────

/// The reuse window for one resolver, or `None` when caching is off for it.
///
/// Most-specific-first, then clamped: the resolver's own `cache_ttl`, else the
/// deployment default; and for a `scope`-bearing resolver, no wider than the
/// deployment's ceiling for those. Templates set defaults, deployments set
/// caps, tighter wins — the same split D56 drew for call timeouts, for the same
/// reason: a template author must not be able to widen their own admin's policy.
pub fn effective_ttl(
    resolver: &overslash_core::types::ParamResolver,
    config: &Config,
) -> Option<Duration> {
    resolve_ttl(
        resolver.cache_ttl,
        resolver.scope.is_some(),
        config.resolve_cache_ttl_secs,
        config.resolve_cache_scope_ttl_max_secs,
    )
}

/// The rule itself, over four numbers. Split out from [`effective_ttl`] so the
/// precedence and the clamp can be tested without assembling a whole `Config`.
fn resolve_ttl(
    declared: Option<u64>,
    canonicalizes: bool,
    deployment_default: u64,
    scope_ceiling: u64,
) -> Option<Duration> {
    // The deployment switch wins over a template asking to be cached —
    // otherwise "turn the cache off" would not turn it off.
    if deployment_default == 0 {
        return None;
    }
    let secs = declared.unwrap_or(deployment_default);
    let secs = if canonicalizes {
        secs.min(scope_ceiling)
    } else {
        secs
    };
    (secs > 0).then(|| Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use overslash_core::types::ParamResolver;

    fn scope() -> CacheScope {
        CacheScope {
            org_id: Uuid::from_u128(1),
            ceiling_user_id: Uuid::from_u128(2),
            instance_id: Some(Uuid::from_u128(3)),
            credential_fingerprint: "acct:a@example.com".into(),
            service_key: "gmail".into(),
            runtime: "http",
            namespace: None,
        }
    }

    fn key_of(s: &CacheScope) -> String {
        s.key("https://x/profile", Some("{emailAddress}"), Some("phone"))
    }

    /// Every field in the preimage has to move the key. The one that matters
    /// most is `credential_fingerprint`: gmail's `userId: me` produces a
    /// byte-identical URL for every user alive, so if that field stopped
    /// reaching the digest, one person's email address would be served into
    /// another person's approval — and into their permission key.
    #[test]
    fn every_preimage_field_changes_the_key() {
        let base = scope();
        let baseline = key_of(&base);

        type Mutation = (&'static str, Box<dyn Fn(&mut CacheScope)>);
        let mutations: Vec<Mutation> = vec![
            (
                "org",
                Box::new(|s: &mut CacheScope| s.org_id = Uuid::from_u128(9)),
            ),
            (
                "owner",
                Box::new(|s: &mut CacheScope| s.ceiling_user_id = Uuid::from_u128(9)),
            ),
            (
                "instance",
                Box::new(|s: &mut CacheScope| s.instance_id = Some(Uuid::from_u128(9))),
            ),
            (
                "no instance",
                Box::new(|s: &mut CacheScope| s.instance_id = None),
            ),
            (
                "credential",
                Box::new(|s: &mut CacheScope| {
                    s.credential_fingerprint = "acct:b@example.com".into()
                }),
            ),
            (
                "service",
                Box::new(|s: &mut CacheScope| s.service_key = "outlook".into()),
            ),
            ("runtime", Box::new(|s: &mut CacheScope| s.runtime = "mcp")),
        ];
        for (label, mutate) in mutations {
            let mut s = base.clone();
            mutate(&mut s);
            assert_ne!(baseline, key_of(&s), "{label} must change the key");
        }

        // ...and so must the target and each half of the projection.
        assert_ne!(
            baseline,
            base.key("https://y/profile", Some("{emailAddress}"), Some("phone"))
        );
        assert_ne!(
            baseline,
            base.key("https://x/profile", Some("{name}"), Some("phone"))
        );
        assert_ne!(
            baseline,
            base.key("https://x/profile", Some("{emailAddress}"), Some("email"))
        );
        assert_ne!(
            baseline,
            base.key("https://x/profile", Some("{emailAddress}"), None)
        );
    }

    /// Length-prefixing, not delimiter-joining. Without it a field that can
    /// contain the separator could shift the boundaries and collide with a
    /// different tuple — and `service_key` is org-authored.
    #[test]
    fn field_boundaries_cannot_be_forged_by_shifting_content() {
        let mut a = scope();
        a.service_key = "gmail".into();
        a.credential_fingerprint = "acct:x".into();

        let mut b = scope();
        b.service_key = "gmail\u{0}acct:x".into();
        b.credential_fingerprint = String::new();

        assert_ne!(key_of(&a), key_of(&b));
    }

    #[test]
    fn the_namespace_segment_partitions_the_keyspace() {
        let plain = scope();
        let mut namespaced = scope();
        namespaced.namespace = Some("ci-run-7".into());
        assert_ne!(key_of(&plain), key_of(&namespaced));
        assert!(key_of(&namespaced).starts_with("osr:v1:ci-run-7:"));
    }

    /// The org id is the one plaintext component, so an org-level purge can
    /// `SCAN` for it and a preimage bug degrades to a miss inside one tenant
    /// rather than across tenants.
    #[test]
    fn the_key_carries_the_org_in_plaintext_and_nothing_else() {
        let s = scope();
        let key = key_of(&s);
        assert!(key.starts_with(&format!("osr:v1::{}:", s.org_id)));
        assert!(!key.contains("gmail"), "service key must not be plaintext");
        assert!(
            !key.contains("example.com"),
            "credential must not be plaintext"
        );
    }

    const SECS: fn(u64) -> Option<Duration> = |s| Some(Duration::from_secs(s));

    #[test]
    fn a_resolver_ttl_overrides_the_deployment_default() {
        assert_eq!(resolve_ttl(Some(3600), false, 300, 300), SECS(3600));
        // ...and an undeclared one inherits it.
        assert_eq!(resolve_ttl(None, false, 300, 300), SECS(300));
    }

    /// A `scope`-bearing resolver is doing authorization work, so the
    /// deployment's ceiling clamps it however wide the template asked for.
    /// Templates set defaults, deployments set caps, tighter wins (D56).
    #[test]
    fn a_scope_resolver_is_clamped_by_the_deployment_ceiling() {
        assert_eq!(resolve_ttl(Some(86_400), true, 300, 300), SECS(300));
        // The identical TTL without `scope` is left alone — a display string
        // decides nothing about which grant matches.
        assert_eq!(resolve_ttl(Some(86_400), false, 300, 300), SECS(86_400));
    }

    #[test]
    fn cache_ttl_zero_opts_a_single_resolver_out() {
        assert_eq!(resolve_ttl(Some(0), false, 300, 300), None);
    }

    /// The deployment switch wins over a template that asks to be cached —
    /// otherwise "turn the cache off" wouldn't actually turn it off.
    #[test]
    fn a_zero_deployment_default_disables_even_an_opted_in_resolver() {
        assert_eq!(resolve_ttl(Some(3600), false, 0, 300), None);
    }

    /// `effective_ttl` is the same rule read off a resolver, so a template
    /// declaring both halves lands where the pure function says it does.
    #[test]
    fn effective_ttl_reads_the_resolver() {
        let mut c = crate::config::tests::empty_test_config();
        c.resolve_cache_ttl_secs = 300;
        c.resolve_cache_scope_ttl_max_secs = 300;
        let r = ParamResolver {
            cache_ttl: Some(86_400),
            scope: Some("phone".into()),
            ..Default::default()
        };
        assert_eq!(effective_ttl(&r, &c), SECS(300));
    }

    fn secret(name: &str) -> overslash_core::types::SecretRef {
        overslash_core::types::SecretRef {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// The fingerprint is the field that keeps one principal's resolutions out
    /// of another's, so every arm needs to be pinned — a wrong-but-*stable*
    /// fingerprint still produces hits and green tests, which is what makes a
    /// regression here silent.
    #[test]
    fn the_http_fingerprint_separates_every_credential_shape() {
        let a = http_credential_fingerprint(Some("a@example.com"), &[], true);
        let b = http_credential_fingerprint(Some("b@example.com"), &[], true);
        assert_ne!(a, b, "two OAuth accounts must not share an entry");

        // The account wins over everything else when it is known.
        assert_eq!(
            a,
            http_credential_fingerprint(Some("a@example.com"), &[secret("x")], true)
        );

        // Explicit `req.secrets` with no connection behind them: the vault
        // reference is the only discriminator there is.
        let one = http_credential_fingerprint(None, &[secret("secret_one")], false);
        let two = http_credential_fingerprint(None, &[secret("secret_two")], false);
        assert_ne!(one, two, "different secret names must not share an entry");
        assert_eq!(
            one,
            http_credential_fingerprint(None, &[secret("secret_one")], false)
        );

        // Slot order must not change the key, or the same credential set would
        // miss half the time.
        assert_eq!(
            http_credential_fingerprint(None, &[secret("a"), secret("b")], false),
            http_credential_fingerprint(None, &[secret("b"), secret("a")], false),
        );

        // Authenticated-but-unnamed must not collapse into anonymous.
        let unnamed = http_credential_fingerprint(None, &[], true);
        let anon = http_credential_fingerprint(None, &[], false);
        assert_ne!(unnamed, anon);
        assert_eq!(anon, "anon");
    }

    #[test]
    fn the_mcp_fingerprint_separates_connection_from_vault_from_anonymous() {
        use overslash_core::types::McpAuth;
        let c1 = Uuid::from_u128(1);
        let c2 = Uuid::from_u128(2);
        let oauth = McpAuth::OAuth {
            provider: "whatsapp".into(),
            scopes: vec![],
        };

        assert_ne!(
            mcp_credential_fingerprint(Some(c1), &oauth),
            mcp_credential_fingerprint(Some(c2), &oauth),
            "two connections must not share an entry"
        );
        // The connection wins over the provider name when one is known.
        assert_eq!(
            mcp_credential_fingerprint(Some(c1), &oauth),
            mcp_credential_fingerprint(Some(c1), &McpAuth::None)
        );

        let bearer = |n: &str| McpAuth::Bearer {
            secret_name: Some(n.to_string()),
        };
        assert_ne!(
            mcp_credential_fingerprint(None, &bearer("tok_a")),
            mcp_credential_fingerprint(None, &bearer("tok_b")),
            "two instances on different vault secrets must not share an entry"
        );
        assert_eq!(mcp_credential_fingerprint(None, &McpAuth::None), "anon");
    }
}
