use std::collections::HashMap;
use std::time::Duration;

use overslash_core::description::substitute_placeholders;
use overslash_core::param_resolver::pick_value;
use overslash_core::types::service::ServiceAction;

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolve human-readable display names for action params that have `resolve` definitions.
///
/// Makes concurrent GET requests to the same service host using the already-authenticated
/// headers. Returns a map of param name → display name for successful resolutions.
/// Failures are silently skipped (the caller falls back to raw param values).
pub async fn resolve_display_params(
    client: &reqwest::Client,
    base_url: &str,
    headers: &HashMap<String, String>,
    action: &ServiceAction,
    params: &HashMap<String, serde_json::Value>,
) -> HashMap<String, String> {
    let resolvers: Vec<_> = action
        .params
        .iter()
        .filter_map(|(name, param)| {
            let resolver = param.resolve.as_ref()?;
            Some((name.clone(), resolver.clone()))
        })
        .collect();

    if resolvers.is_empty() {
        return HashMap::new();
    }

    let futures: Vec<_> = resolvers
        .into_iter()
        .map(|(name, resolver)| {
            let client = client.clone();
            let base_url = base_url.to_string();
            let headers = headers.clone();
            let params = params.clone();

            async move {
                let path = substitute_placeholders(&resolver.get, &params);
                let url = format!("{base_url}{path}");

                let mut req = client.get(&url).timeout(RESOLVE_TIMEOUT);
                for (key, value) in &headers {
                    req = req.header(key, value);
                }

                let resp = req.send().await.ok()?;
                if !resp.status().is_success() {
                    return None;
                }

                let json: serde_json::Value = resp.json().await.ok()?;
                let display = pick_value(&json, &resolver.pick)?;
                Some((name, display))
            }
        })
        .collect();

    let results = futures_util::future::join_all(futures).await;

    results.into_iter().flatten().collect()
}
