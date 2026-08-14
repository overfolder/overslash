//! Turn opaque IDs into something a human can review.
//!
//! A permission gate shows the reviewer whatever the agent passed. For an
//! `{id}`-shaped argument that is unreadable — `239135323373760@lid` names a
//! person only to WhatsApp — so a template can declare a resolver on the
//! param and have the gateway look the value up before the approval is
//! minted. Two runtimes, one contract:
//!
//! - **HTTP** — `get:` is fetched with an authenticated GET against the same
//!   service host, and the projection runs over the response body.
//! - **MCP** — `tool:` names a sibling `risk: read` tool, called with `args:`
//!   over the same transport as a real dispatch, and the projection runs over
//!   the tool's structured result.
//!
//! Resolution is best-effort by design: every failure is dropped silently and
//! the caller falls back to the raw argument. A provider being down must
//! degrade the *readability* of an approval, never block one from being
//! raised.
//!
//! Answers are cached (D64) — see [`crate::services::resolve_cache`], which
//! also explains why a cached `scope` value is an authorization decision and
//! not merely a latency optimisation. The lookup is threaded in as a
//! [`ResolverPlan`] built by the *caller*, before it assembles credentials,
//! because on both runtimes the expensive part is the preamble: an HTTP
//! resolver's headers cost a vault decrypt, and an MCP resolver's client costs
//! vault reads plus blocking DNS. A plan that is all hits lets the caller skip
//! that entirely.

use std::collections::HashMap;
use std::time::Duration;

use overslash_core::param_resolver::{pick_value, render_display};
use overslash_core::types::service::ServiceAction;
use overslash_core::types::{AuthHeader, McpAuth};
use overslash_db::scopes::OrgScope;

use crate::AppState;
use crate::services::resolve_cache::{
    PlanEntry, ResolverOutcome, ResolverPlan, http_target, mcp_arguments,
};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// What an action's resolvers produced.
///
/// Two maps rather than one richer value because they feed two unrelated
/// consumers: `display` is cosmetic and reaches the summary line and the jq
/// `.resolved` projection, while `canonical` reaches
/// `PermissionKey::from_service_action` and therefore decides which grants
/// match. Keeping them apart makes it hard to accidentally mint a permission
/// against a value that was only ever meant to be read.
#[derive(Debug, Clone, Default)]
pub struct ResolvedParams {
    /// Param name → human-readable display string.
    pub display: HashMap<String, String>,
    /// Param name → canonical scope value for the permission key.
    pub canonical: HashMap<String, String>,
}

impl ResolvedParams {
    /// Fold one resolution into the two maps. Used for cached and freshly
    /// fetched answers alike — an absent half contributes nothing, which is
    /// the same shape a live failure leaves behind.
    fn insert_resolution(&mut self, param: &str, display: Option<&str>, canonical: Option<&str>) {
        if let Some(d) = display {
            self.display.insert(param.to_string(), d.to_string());
        }
        if let Some(c) = canonical {
            self.canonical.insert(param.to_string(), c.to_string());
        }
    }
}

/// Project a resolver response into its display string and canonical value.
fn project(
    resolver: &overslash_core::types::ParamResolver,
    body: &serde_json::Value,
) -> (Option<String>, Option<String>) {
    let display = resolver
        .display_template()
        .and_then(|template| render_display(&template, body));
    let canonical = resolver
        .scope
        .as_deref()
        .and_then(|path| pick_value(body, path))
        .filter(|v| !v.trim().is_empty());
    (display, canonical)
}

/// Resolve display names for HTTP-runtime action params that declare `get:`.
///
/// Makes concurrent GET requests to the same service host using the already-
/// authenticated headers. Failures are silently skipped (the caller falls
/// back to raw param values).
///
/// Resolver URLs honor `service_base_overrides` the same way the executor
/// does — an e2e stack that rewrites a service's host to a local fake needs
/// the resolver GETs to land there too, not on the real provider.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_display_params(
    client: &reqwest::Client,
    config: &crate::config::Config,
    base_url: &str,
    headers: &HashMap<String, String>,
    action: &ServiceAction,
    params: &HashMap<String, serde_json::Value>,
    cache: &dyn crate::services::resolve_cache::ResolveCacheStore,
    plan: &ResolverPlan,
) -> ResolvedParams {
    let mut out = ResolvedParams::default();
    for (name, cached) in plan.hits() {
        out.insert_resolution(name, cached.d.as_deref(), cached.c.as_deref());
    }

    // Only the params the cache could not answer.
    let resolvers: Vec<_> = action
        .params
        .iter()
        .filter_map(|(name, param)| {
            let resolver = param.resolve.as_ref()?;
            let get = resolver.get.as_ref()?;
            // Only a hit is skipped. A param the plan says nothing about
            // resolves live and simply isn't written back — the plan is built
            // from this same action so that should be unreachable, but the
            // failure mode of guessing wrong is "a resolver silently stopped
            // running", which is the bug D55's rationale was written about.
            match plan.get(name) {
                Some(PlanEntry::Hit(_)) => None,
                _ => Some((name.clone(), resolver.clone(), get.clone())),
            }
        })
        .collect();

    if resolvers.is_empty() {
        return out;
    }

    let futures: Vec<_> = resolvers
        .into_iter()
        .map(|(name, resolver, get)| {
            let client = client.clone();
            let headers = headers.clone();
            // Shared with the key builder so the cache key and the outgoing
            // request cannot disagree about what was asked.
            let url = http_target(config, base_url, &get, params);

            async move {
                let fetched = async {
                    let mut req = client.get(&url).timeout(RESOLVE_TIMEOUT);
                    for (key, value) in &headers {
                        req = req.header(key, value);
                    }
                    let resp = req.send().await.ok()?;
                    if !resp.status().is_success() {
                        return None;
                    }
                    let json: serde_json::Value = resp.json().await.ok()?;
                    Some(project(&resolver, &json))
                }
                .await;
                (name, fetched)
            }
        })
        .collect();

    let fetched: Vec<ResolverOutcome> = futures_util::future::join_all(futures).await;

    // A failed HTTP resolver GET is the provider's answer (a 404, a 5xx, a
    // timeout), so it is cacheable — that is the case where a negative entry
    // earns the most, converting a repeated 3s stall into an instant miss.
    crate::services::resolve_cache::write_back(cache, config, plan, &fetched, true).await;

    for (name, outcome) in fetched {
        if let Some((display, canonical)) = outcome {
            out.insert_resolution(&name, display.as_deref(), canonical.as_deref());
        }
    }
    out
}

/// Resolve display names for MCP-runtime action params that declare `tool:`.
///
/// Dispatches each resolver as a real `tools/call` against the same instance
/// the action itself would hit, sharing `mcp_caller::build_client` so auth,
/// SSRF pinning and host overrides cannot drift from the dispatch path.
///
/// `template_validation` guarantees the named tool is `risk: read`, so this
/// cannot mutate anything on the way to an approval. Resolvers are not
/// recursive: the tool is invoked directly rather than through the action
/// pipeline, so a resolver on the *resolver's* params is never consulted.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_display_params_mcp(
    state: &AppState,
    scope: &OrgScope,
    url: &str,
    auth: &McpAuth,
    oauth_header: Option<&AuthHeader>,
    action: &ServiceAction,
    params: &HashMap<String, serde_json::Value>,
    cache: &dyn crate::services::resolve_cache::ResolveCacheStore,
    plan: &ResolverPlan,
) -> ResolvedParams {
    let mut out = ResolvedParams::default();
    for (name, cached) in plan.hits() {
        out.insert_resolution(name, cached.d.as_deref(), cached.c.as_deref());
    }

    let resolvers: Vec<_> = action
        .params
        .iter()
        .filter_map(|(name, param)| {
            let resolver = param.resolve.as_ref()?;
            let tool = resolver.tool.as_ref()?;
            // As above: skip only a hit, never an absence.
            match plan.get(name) {
                Some(PlanEntry::Hit(_)) => None,
                _ => Some((name.clone(), resolver.clone(), tool.clone())),
            }
        })
        .collect();

    // Every resolver answered from cache — return without building a client.
    // This is the branch the whole two-phase shape exists for: `build_client`
    // reads the vault and resolves the host through a blocking
    // `to_socket_addrs`, all while an approval is being minted.
    if resolvers.is_empty() {
        return out;
    }

    // One client for the whole fan-out: `build_client` resolves secrets from
    // the vault, so building it per resolver would multiply vault reads by
    // the number of resolvers on the action.
    //
    // One deadline for the whole phase, shared by the client build and every
    // tools/call, so the documented budget is what the approval path actually
    // pays — two sequential `timeout`s would make it 2×. `build_client` is
    // inside it because it reaches `ssrf_guard::build_pinned_client`, whose
    // host resolution is a blocking `to_socket_addrs` with no deadline of its
    // own, and this all runs synchronously while an approval is minted.
    let deadline = tokio::time::Instant::now() + RESOLVE_TIMEOUT;
    let built = tokio::time::timeout_at(
        deadline,
        crate::services::mcp_caller::build_client(state, scope, url, auth, oauth_header),
    )
    .await;
    let (client, headers) = match built {
        Ok(Ok(pair)) => pair,
        // Degraded, not fatal — but this is the only place a resolver
        // misconfiguration can surface. `mcp_caller::invoke` never runs on a
        // gated call, so without this line the operator sees approvals
        // quoting raw handles forever with nothing to grep for.
        // Nothing is written back on either arm below. The failure is *ours*
        // — a credential that would not build, a host that would not resolve —
        // not an answer from the provider, and caching it would turn a
        // transient local misconfiguration into a sticky one on every replica.
        Ok(Err(e)) => {
            tracing::warn!(
                action = %action.mcp_tool.as_deref().unwrap_or_default(),
                error = %e,
                "mcp display-param resolution skipped: could not build client"
            );
            crate::services::resolve_cache::write_back(cache, &state.config, plan, &[], false)
                .await;
            return out;
        }
        Err(_) => {
            tracing::warn!(
                action = %action.mcp_tool.as_deref().unwrap_or_default(),
                timeout_ms = RESOLVE_TIMEOUT.as_millis(),
                "mcp display-param resolution skipped: client build timed out"
            );
            crate::services::resolve_cache::write_back(cache, &state.config, plan, &[], false)
                .await;
            return out;
        }
    };

    let futures: Vec<_> = resolvers
        .into_iter()
        .map(|(name, resolver, tool)| {
            let client = client.clone();
            let headers = headers.clone();
            // Shared with the key builder so the cache key and the outgoing
            // call can never disagree about what was asked.
            let arguments = mcp_arguments(&resolver, params);

            async move {
                let outcome = async {
                    let result = match tokio::time::timeout_at(
                        deadline,
                        client.tools_call(&headers, &tool, &arguments),
                    )
                    .await
                    {
                        Ok(Ok(result)) if !result.is_error => result,
                        // In-band: the tool ran and said "no". A JID nobody has
                        // messaged is the ordinary case, so this is not a warning.
                        Ok(Ok(_)) => {
                            tracing::debug!(
                                tool = %tool,
                                param = %name,
                                "mcp resolver reported no result; using the raw argument"
                            );
                            return None;
                        }
                        // Transport, auth, HTTP status or JSON-RPC error — a
                        // renamed tool, an expired token, a 5xx. `warn` because
                        // the deployed default is RUST_LOG=info and this silently
                        // changes which permission keys are minted.
                        Ok(Err(e)) => {
                            tracing::warn!(
                                tool = %tool,
                                param = %name,
                                error = %e,
                                "mcp display-param resolver failed; using the raw argument"
                            );
                            return None;
                        }
                        Err(_) => {
                            tracing::warn!(
                                tool = %tool,
                                param = %name,
                                timeout_ms = RESOLVE_TIMEOUT.as_millis(),
                                "mcp display-param resolver timed out; using the raw argument"
                            );
                            return None;
                        }
                    };
                    let Some(body) = resolver_body(&result) else {
                        tracing::warn!(
                            tool = %tool,
                            param = %name,
                            "mcp resolver returned neither structuredContent nor a JSON text \
                             block; using the raw argument"
                        );
                        return None;
                    };
                    let (display, canonical) = project(&resolver, &body);
                    // Schema drift lands here: the call succeeded but the declared
                    // dot-paths found nothing. Worth a warning because a missing
                    // `scope` value silently reverts the permission key to the raw
                    // argument, so previously-granted rules stop matching.
                    let (has_display, has_scope) = (display.is_some(), canonical.is_some());
                    if !has_display || (resolver.scope.is_some() && !has_scope) {
                        tracing::warn!(
                            tool = %tool,
                            param = %name,
                            has_display,
                            has_scope,
                            "mcp resolver answered but the declared paths found nothing"
                        );
                    }
                    Some((display, canonical))
                }
                .await;
                (name, outcome)
            }
        })
        .collect();

    let fetched: Vec<ResolverOutcome> = futures_util::future::join_all(futures).await;

    // Cacheable: by this point the client built, so every outcome above is
    // something the *server* said — a result, an in-band "no", a transport
    // error, or a timeout. All four are the provider's answer.
    crate::services::resolve_cache::write_back(cache, &state.config, plan, &fetched, true).await;

    for (name, outcome) in fetched {
        if let Some((display, canonical)) = outcome {
            out.insert_resolution(&name, display.as_deref(), canonical.as_deref());
        }
    }
    out
}

/// The JSON a resolver's dot-paths address.
///
/// `structuredContent` when the server sends it, otherwise the first text
/// content block parsed as JSON. Servers differ on which they emit for the
/// same tool, and a template author should not have to guess — `pick: phone`
/// means the same thing either way, matching how the HTTP path projects over
/// a plain response body.
fn resolver_body(
    result: &crate::services::mcp_client::ToolCallResult,
) -> Option<serde_json::Value> {
    if let Some(structured) = result.structured.as_ref()
        && !structured.is_null()
    {
        return Some(structured.clone());
    }
    let text = result
        .content
        .as_array()?
        .iter()
        .find_map(|block| block.get("text").and_then(serde_json::Value::as_str))?;
    serde_json::from_str(text).ok()
}

#[cfg(test)]
mod tests {
    use super::{project, resolver_body};
    use crate::services::mcp_client::ToolCallResult;
    use overslash_core::types::ParamResolver;
    use serde_json::json;

    fn result(structured: Option<serde_json::Value>, content: serde_json::Value) -> ToolCallResult {
        ToolCallResult {
            content,
            structured,
            is_error: false,
        }
    }

    #[test]
    fn structured_content_is_the_projection_body() {
        let r = result(Some(json!({"name": "Sonia"})), json!(null));
        assert_eq!(resolver_body(&r), Some(json!({"name": "Sonia"})));
    }

    /// Servers differ on whether they emit `structuredContent`; a template
    /// author writing `pick: phone` should not have to know which. D55
    /// documents this fallback as a contract.
    #[test]
    fn falls_back_to_a_json_text_block_when_structured_is_absent() {
        let payload = json!({"name": "Sonia", "phone": "+34600111222"});
        for structured in [None, Some(json!(null))] {
            let r = result(
                structured,
                json!([{"type": "text", "text": payload.to_string()}]),
            );
            assert_eq!(resolver_body(&r), Some(payload.clone()));
        }
    }

    #[test]
    fn a_non_json_text_block_yields_nothing() {
        let r = result(None, json!([{"type": "text", "text": "not paired"}]));
        assert_eq!(resolver_body(&r), None);
    }

    #[test]
    fn projection_splits_display_from_the_canonical_scope_value() {
        let resolver = ParamResolver {
            tool: Some("resolve_jid".into()),
            display: Some("{name}[ ({phone})]".into()),
            scope: Some("phone".into()),
            ..Default::default()
        };
        let body = json!({"name": "Sonia Pérez", "phone": "+34600111222"});
        assert_eq!(
            project(&resolver, &body),
            (
                Some("Sonia Pérez (+34600111222)".to_string()),
                Some("+34600111222".to_string())
            )
        );
    }

    /// An empty `phone` must not become a canonical permission-key value —
    /// `recipient=` would be a grant on the empty string.
    #[test]
    fn a_blank_scope_value_yields_no_canonical() {
        let resolver = ParamResolver {
            tool: Some("resolve_jid".into()),
            display: Some("{name}".into()),
            scope: Some("phone".into()),
            ..Default::default()
        };
        let body = json!({"name": "Peluquería canina", "phone": ""});
        assert_eq!(
            project(&resolver, &body),
            (Some("Peluquería canina".to_string()), None)
        );
    }
}
