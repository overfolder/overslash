//! Cache for `x-overslash-resolve` answers (D64).
//!
//! A resolver turns an opaque argument into something a reviewer can read, at
//! the cost of an authenticated round trip *per call* — `services/gmail.yaml`
//! asks the same `/gmail/v1/users/me/profile` question on nineteen actions, and
//! the answer only changes when the connection does. This caches it.
//!
//! # This is not a transparent cache
//!
//! A resolver's `scope:` value canonicalizes the **permission key**, while the
//! outgoing request keeps the caller's raw argument (D55). Live, those two are
//! consistent by construction: the canonical value is derived microseconds
//! before the key is built. Cached, they are not — the key reflects the mapping
//! as of up to a TTL ago, the call targets the mapping as of now. If a WhatsApp
//! JID is re-pointed at a different person inside the window, a grant minted
//! for the old person still matches.
//!
//! That is why the default TTL is short, why `scope`-bearing resolvers are
//! clamped harder ([`Config::resolve_cache_scope_ttl_max_secs`]), and why the
//! knob lives on the template: only the author knows whether the mapping is
//! immutable. Everything *else* about a cache miss fails closed — no canonical
//! value means the key stays the raw argument, matches no grant, and gates.
//!
//! # Layering
//!
//! [`ResolveCacheStore`] is deliberately byte-oriented. Encryption and
//! projection live above it, so both backends store identical ciphertext and
//! there is exactly one place where a plaintext name becomes bytes.

//!
//! Split three ways: `store` owns the backends and the factory, `key` owns the
//! preimage and the TTL rule, and this file owns the value shape and the
//! two-phase plan that ties them together.

mod key;
mod store;

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use overslash_core::description::substitute_placeholders;
use overslash_core::types::service::ServiceAction;

use crate::config::Config;

pub use key::{
    CacheScope, effective_ttl, http_credential_fingerprint, mcp_credential_fingerprint, mcp_target,
};
pub use store::{InMemoryResolveCache, ResolveCacheStore, Slot, create_resolve_cache, in_memory};

/// Value-shape version, independent of the `v1` in the key namespace. An entry
/// tagged with an unknown version is treated as a miss, so a rolling deploy
/// where two replicas disagree degrades to extra upstream calls rather than to
/// garbage in an approval.
const VALUE_VERSION: u8 = 1;

// ── Value ───────────────────────────────────────────────────────────

/// What one resolver produced this call: the param it belongs to, and
/// `Some((display, canonical))` when it answered — `None` when it did not.
///
/// The nested `Option`s are all load-bearing and distinct: the outer one is
/// "did the resolver answer at all", and the inner two are the two independent
/// projections, either of which can be absent from an answer that *did* arrive.
pub type ResolverOutcome = (String, Option<(Option<String>, Option<String>)>);

/// What one resolver produced, as stored.
///
/// `neg` is **not** redundant with `d: None, c: None`. A resolver that ran and
/// answered can legitimately project to nothing — `param_resolver` warns about
/// exactly that case — and that is a *positive* result held at the success
/// TTL. `neg` marks the other thing: the resolver did not answer, held at the
/// much shorter failure TTL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedResolution {
    pub v: u8,
    pub neg: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
}

impl CachedResolution {
    pub fn positive(display: Option<String>, canonical: Option<String>) -> Self {
        Self {
            v: VALUE_VERSION,
            neg: false,
            d: display,
            c: canonical,
        }
    }

    pub fn negative() -> Self {
        Self {
            v: VALUE_VERSION,
            neg: true,
            d: None,
            c: None,
        }
    }
}

// ── Plan ────────────────────────────────────────────────────────────

/// What one resolver needs from the cache.
pub enum PlanEntry {
    /// Reuse this; make no upstream call.
    Hit(CachedResolution),
    /// Resolve live, then write back under `key`.
    Miss { key: String, ttl: Duration },
    /// Caching is off for this resolver; resolve live and store nothing.
    Disabled,
}

/// The cache's answer for every resolver on one action.
#[derive(Default)]
pub struct ResolverPlan {
    entries: HashMap<String, PlanEntry>,
}

impl ResolverPlan {
    /// True when nothing needs an upstream call.
    ///
    /// This is what lets the caller skip the *expensive* preamble entirely —
    /// on HTTP the credential decrypt that builds resolver headers, on MCP the
    /// `build_client` that does vault reads and blocking DNS. Deliberately
    /// false for an empty plan: "no resolvers" is the caller's own early
    /// return, not a cache hit.
    pub fn all_hit(&self) -> bool {
        !self.entries.is_empty()
            && self
                .entries
                .values()
                .all(|e| matches!(e, PlanEntry::Hit(_)))
    }

    pub fn get(&self, param: &str) -> Option<&PlanEntry> {
        self.entries.get(param)
    }

    /// The cached resolutions, ready to fold into `ResolvedParams`.
    pub fn hits(&self) -> impl Iterator<Item = (&String, &CachedResolution)> {
        self.entries.iter().filter_map(|(name, e)| match e {
            PlanEntry::Hit(c) => Some((name, c)),
            _ => None,
        })
    }

    /// Where to write `param`'s freshly-resolved answer, if anywhere.
    pub fn write_target(&self, param: &str) -> Option<(&str, Duration)> {
        match self.entries.get(param) {
            Some(PlanEntry::Miss { key, ttl }) => Some((key.as_str(), *ttl)),
            _ => None,
        }
    }
}

/// Build the plan: derive a key per resolver, read them all in one round trip,
/// and classify.
///
/// `targets` is `(param name, resolver, target string)` — the caller supplies
/// the target because only it knows how to build one (a substituted URL on
/// HTTP, a url+tool+args triple on MCP).
pub async fn plan(
    store: &dyn ResolveCacheStore,
    config: &Config,
    scope: &CacheScope,
    targets: Vec<(String, overslash_core::types::ParamResolver, String)>,
) -> ResolverPlan {
    let mut plan = ResolverPlan::default();
    if targets.is_empty() {
        return plan;
    }

    let keyring = config.keyring().ok();

    let mut lookups: Vec<(String, String, Duration)> = Vec::new();
    for (name, resolver, target) in targets {
        match effective_ttl(&resolver, config) {
            None => {
                overslash_metrics::resolve_cache::record_lookup(store.backend(), "disabled");
                plan.entries.insert(name, PlanEntry::Disabled);
            }
            Some(ttl) => {
                let key = scope.key(
                    &target,
                    resolver.display_template().as_deref(),
                    resolver.scope.as_deref(),
                );
                lookups.push((name, key, ttl));
            }
        }
    }
    if lookups.is_empty() {
        return plan;
    }

    // Without a keyring we cannot read or write values, so behave as if the
    // cache were off rather than storing plaintext PII.
    let Some(keyring) = keyring else {
        tracing::warn!("resolve cache disabled: encryption key unavailable");
        for (name, _, _) in lookups {
            overslash_metrics::resolve_cache::record_lookup(store.backend(), "disabled");
            plan.entries.insert(name, PlanEntry::Disabled);
        }
        return plan;
    };

    let keys: Vec<String> = lookups.iter().map(|(_, k, _)| k.clone()).collect();
    let values = store.get_many(&keys).await;

    for ((name, key, ttl), value) in lookups.into_iter().zip(values) {
        // An entry that is present but unreadable is *not* the same as a cold
        // key, and folding the two together is the failure mode this module's
        // own doc calls hardest to notice: a keyring rotation that dropped the
        // previous key, or two deployments sharing a Valkey without
        // `RESOLVE_CACHE_NAMESPACE`, would show a healthy-looking 0% hit rate
        // forever while every call quietly paid the upstream round trip again.
        let cached = match &value {
            Slot::Hit(blob) => overslash_core::crypto::decrypt(&keyring, blob)
                .ok()
                .and_then(|plain| serde_json::from_slice::<CachedResolution>(&plain).ok())
                .filter(|c| c.v == VALUE_VERSION),
            Slot::Absent | Slot::Failed => None,
        };

        match cached {
            Some(c) => {
                let outcome = if c.neg {
                    "hit_negative"
                } else {
                    "hit_positive"
                };
                overslash_metrics::resolve_cache::record_lookup(store.backend(), outcome);
                plan.entries.insert(name, PlanEntry::Hit(c));
            }
            None => {
                match value {
                    Slot::Hit(_) => {
                        tracing::warn!(
                            param = %name,
                            "resolve cache entry could not be read (key rotation, a shared \
                             keyspace, or a corrupt value); resolving live"
                        );
                        overslash_metrics::resolve_cache::record_lookup(
                            store.backend(),
                            "unreadable",
                        );
                    }
                    // Already counted once per batch by the backend; counting
                    // it again per key would inflate the miss denominator with
                    // a single outage.
                    Slot::Failed => {}
                    Slot::Absent => {
                        overslash_metrics::resolve_cache::record_lookup(store.backend(), "miss")
                    }
                }
                plan.entries.insert(name, PlanEntry::Miss { key, ttl });
            }
        }
    }
    plan
}

/// Write freshly-resolved answers back.
///
/// `results` is `(param name, outcome)`, where `None` means the resolver did
/// not answer. `cacheable` is false when the failure was *ours* — a credential
/// that would not build, an MCP client that could not be constructed — because
/// caching those turns a transient local misconfiguration into a sticky one
/// across every replica. A provider that 404s or times out is a real answer and
/// is cached.
pub async fn write_back(
    store: &dyn ResolveCacheStore,
    config: &Config,
    plan: &ResolverPlan,
    results: &[ResolverOutcome],
    cacheable: bool,
) {
    if !cacheable || results.is_empty() {
        if !cacheable {
            overslash_metrics::resolve_cache::record_write(store.backend(), "suppressed");
        }
        return;
    }
    let Ok(keyring) = config.keyring() else {
        // `plan()` warns on the same condition; a silent return here would mean
        // a deployment with a bad key writes nothing forever with no signal.
        tracing::warn!("resolve cache write skipped: encryption key unavailable");
        overslash_metrics::resolve_cache::record_write(store.backend(), "error");
        return;
    };
    let negative_ttl = Duration::from_secs(config.resolve_cache_negative_ttl_secs);

    let mut writes: Vec<(String, Vec<u8>, Duration)> = Vec::new();
    for (name, outcome) in results {
        let Some((key, ttl)) = plan.write_target(name) else {
            continue;
        };
        let (value, ttl, kind) = match outcome {
            Some((display, canonical)) => (
                CachedResolution::positive(display.clone(), canonical.clone()),
                ttl,
                "positive",
            ),
            // A negative TTL of 0 means "never remember a failure".
            None if negative_ttl.is_zero() => continue,
            None => (CachedResolution::negative(), negative_ttl, "negative"),
        };
        let Ok(plain) = serde_json::to_vec(&value) else {
            overslash_metrics::resolve_cache::record_write(store.backend(), "error");
            continue;
        };
        // Encrypted because what a resolver returns is people's names,
        // addresses and phone numbers — and with Valkey that leaves the
        // process for a store shared with the URL shortener.
        let Ok(blob) = overslash_core::crypto::encrypt(&keyring, &plain) else {
            // Counted, not swallowed: a systematic encrypt failure would
            // otherwise drop 100% of writes while the counters stayed flat.
            tracing::warn!(param = %name, "resolve cache value could not be encrypted");
            overslash_metrics::resolve_cache::record_write(store.backend(), "error");
            continue;
        };
        overslash_metrics::resolve_cache::record_write(store.backend(), kind);
        writes.push((key.to_string(), blob, ttl));
    }
    store.put_many(&writes).await;
}

/// The resolvers on `action` that apply to the HTTP runtime, with their
/// substituted target URLs.
pub fn http_targets(
    config: &Config,
    base_url: &str,
    action: &ServiceAction,
    params: &HashMap<String, serde_json::Value>,
) -> Vec<(String, overslash_core::types::ParamResolver, String)> {
    action
        .params
        .iter()
        .filter_map(|(name, param)| {
            let resolver = param.resolve.as_ref()?;
            let get = resolver.get.as_ref()?;
            let url = http_target(config, base_url, get, params);
            Some((name.clone(), resolver.clone(), url))
        })
        .collect()
}

/// The resolvers on `action` that apply to the MCP runtime, with their
/// substituted `tools/call` targets.
pub fn mcp_targets(
    resolved_url: &str,
    action: &ServiceAction,
    params: &HashMap<String, serde_json::Value>,
) -> Vec<(String, overslash_core::types::ParamResolver, String)> {
    action
        .params
        .iter()
        .filter_map(|(name, param)| {
            let resolver = param.resolve.as_ref()?;
            let tool = resolver.tool.as_ref()?;
            let arguments = mcp_arguments(resolver, params);
            let target = mcp_target(resolved_url, tool, &arguments);
            Some((name.clone(), resolver.clone(), target))
        })
        .collect()
}

/// The URL one HTTP resolver fetches, with `{param}` placeholders substituted
/// and deployment base overrides applied.
///
/// Shared with the key builder for the same reason [`mcp_arguments`] is: the
/// key and the outgoing request must not be able to disagree about what was
/// asked. If they drift, the failure is invisible — either a permanent 0% hit
/// rate, or worse, a hit keyed on a URL other than the one being called.
pub fn http_target(
    config: &Config,
    base_url: &str,
    get: &str,
    params: &HashMap<String, serde_json::Value>,
) -> String {
    let path = substitute_placeholders(get, params);
    config.apply_base_overrides(&format!("{base_url}{path}"))
}

/// The `tools/call` arguments for one resolver, with `{param}` placeholders
/// substituted. Shared so the key and the outgoing call cannot disagree about
/// what was asked.
pub fn mcp_arguments(
    resolver: &overslash_core::types::ParamResolver,
    params: &HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    serde_json::Value::Object(
        resolver
            .args
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::Value::String(substitute_placeholders(v, params)),
                )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// what separates the two, which is why it is not redundant with two
    /// `None` fields.
    #[test]
    fn an_empty_projection_is_still_a_positive_entry() {
        let empty = CachedResolution::positive(None, None);
        assert!(!empty.neg);
        assert_ne!(empty, CachedResolution::negative());
    }

    use crate::services::resolve_cache::store::Slot;
    use overslash_core::types::ParamResolver;

    fn cfg() -> Config {
        crate::config::tests::empty_test_config()
    }

    fn scope() -> CacheScope {
        CacheScope {
            org_id: uuid::Uuid::from_u128(1),
            ceiling_user_id: uuid::Uuid::from_u128(2),
            instance_id: None,
            credential_fingerprint: "anon".into(),
            service_key: "svc".into(),
            runtime: "http",
            namespace: None,
        }
    }

    fn targets(resolver: ParamResolver) -> Vec<(String, ParamResolver, String)> {
        vec![("p".to_string(), resolver, "https://x/thing".to_string())]
    }

    fn picky() -> ParamResolver {
        ParamResolver {
            get: Some("/thing".into()),
            pick: Some("name".into()),
            ..Default::default()
        }
    }

    /// A failed resolver is remembered, so a provider that is down costs the
    /// 3s timeout once rather than on every call — and it is remembered as
    /// *negative*, which contributes no canonical value, so the permission key
    /// stays the raw argument and still gates.
    #[tokio::test]
    async fn a_failure_is_written_negative_and_read_back_as_a_hit() {
        let store = in_memory(10);
        let cfg = cfg();

        let first = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        write_back(
            store.as_ref(),
            &cfg,
            &first,
            &[("p".to_string(), None)],
            true,
        )
        .await;

        let second = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        let (_, cached) = second.hits().next().expect("negative entry is a hit");
        assert!(cached.neg);
        assert!(cached.d.is_none() && cached.c.is_none());
        assert!(
            second.all_hit(),
            "a negative hit still skips the upstream call"
        );
    }

    /// A local failure — our credential build, not the provider's answer — must
    /// not be remembered, or a transient misconfiguration becomes sticky on
    /// every replica for the negative TTL.
    #[tokio::test]
    async fn an_uncacheable_failure_is_not_remembered() {
        let store = in_memory(10);
        let cfg = cfg();

        let first = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        write_back(store.as_ref(), &cfg, &first, &[], false).await;

        let second = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        assert_eq!(second.hits().count(), 0, "nothing should have been stored");
    }

    /// A zero negative TTL means "never remember a failure".
    #[tokio::test]
    async fn a_zero_negative_ttl_writes_nothing() {
        let store = in_memory(10);
        let mut cfg = cfg();
        cfg.resolve_cache_negative_ttl_secs = 0;

        let first = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        write_back(
            store.as_ref(),
            &cfg,
            &first,
            &[("p".to_string(), None)],
            true,
        )
        .await;

        let second = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        assert_eq!(second.hits().count(), 0);
    }

    /// What lands in the store is ciphertext. With Valkey this leaves the
    /// process for a keyspace shared with the URL shortener, and what a
    /// resolver returns is people's names and phone numbers.
    #[tokio::test]
    async fn stored_values_are_encrypted() {
        let store = in_memory(10);
        let cfg = cfg();

        let first = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        let (key, _) = match first.entries.get("p") {
            Some(PlanEntry::Miss { key, ttl }) => (key.clone(), *ttl),
            _ => panic!("expected a miss"),
        };
        write_back(
            store.as_ref(),
            &cfg,
            &first,
            &[(
                "p".to_string(),
                Some((Some("Sonia Pérez".into()), Some("+34600111222".into()))),
            )],
            true,
        )
        .await;

        let Slot::Hit(blob) = store.get_many(&[key]).await.remove(0) else {
            panic!("entry should be stored");
        };
        let raw = String::from_utf8_lossy(&blob);
        assert!(
            !raw.contains("Sonia"),
            "the display name must not be plaintext"
        );
        assert!(
            !raw.contains("+34600111222"),
            "the phone must not be plaintext"
        );

        // ...and it round-trips.
        let second = plan(store.as_ref(), &cfg, &scope(), targets(picky())).await;
        let (_, cached) = second.hits().next().expect("hit");
        assert_eq!(cached.d.as_deref(), Some("Sonia Pérez"));
        assert_eq!(cached.c.as_deref(), Some("+34600111222"));
    }

    /// `all_hit()` gates whether resolver credentials get built at all, so an
    /// empty plan must not read as "everything is cached".
    #[tokio::test]
    async fn an_empty_plan_is_not_all_hit() {
        let store = in_memory(10);
        let first = plan(store.as_ref(), &cfg(), &scope(), vec![]).await;
        assert!(!first.all_hit());
    }

    /// Caching off for a resolver means it is neither read nor written.
    #[tokio::test]
    async fn a_disabled_resolver_is_never_stored() {
        let store = in_memory(10);
        let cfg = cfg();
        let opted_out = ParamResolver {
            cache_ttl: Some(0),
            ..picky()
        };

        let first = plan(store.as_ref(), &cfg, &scope(), targets(opted_out.clone())).await;
        assert!(matches!(first.entries.get("p"), Some(PlanEntry::Disabled)));
        write_back(
            store.as_ref(),
            &cfg,
            &first,
            &[("p".to_string(), Some((Some("x".into()), None)))],
            true,
        )
        .await;

        let second = plan(store.as_ref(), &cfg, &scope(), targets(opted_out)).await;
        assert_eq!(second.hits().count(), 0);
    }
}
