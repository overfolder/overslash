use std::collections::HashMap;
use std::time::Instant;

use overslash_core::types::ActionResult;

/// Execute an HTTP request with pre-resolved headers.
pub async fn execute(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> Result<ActionResult, reqwest::Error> {
    let start = Instant::now();

    let method = method
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, url);

    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if let Some(body) = body {
        // Set Content-Type to application/json if not already provided by headers
        if !headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"))
        {
            builder = builder.header("Content-Type", "application/json");
        }
        builder = builder.body(body.to_string());
    }

    let response = builder.send().await?;
    let status_code = response.status().as_u16();

    let resp_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = response.text().await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(ActionResult {
        status_code,
        headers: resp_headers,
        body,
        duration_ms,
    })
}
