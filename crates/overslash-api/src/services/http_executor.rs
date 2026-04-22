use std::collections::HashMap;
use std::time::Instant;

use overslash_core::types::ActionResult;

/// Errors from HTTP execution.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error(transparent)]
    Request(#[from] reqwest::Error),

    #[error("response too large")]
    ResponseTooLarge {
        content_length: Option<u64>,
        content_type: Option<String>,
        limit_bytes: usize,
    },
}

/// Build a reqwest request from the given parameters.
fn build_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> reqwest::RequestBuilder {
    let method = method
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, url);

    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if let Some(body) = body {
        if !headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"))
        {
            builder = builder.header("Content-Type", "application/json");
        }
        builder = builder.body(body.to_string());
    }

    builder
}

/// Execute an HTTP request, buffering the response. Returns an error if the
/// response body exceeds `max_body_bytes`.
pub async fn execute(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    max_body_bytes: usize,
) -> Result<ActionResult, ExecuteError> {
    let start = Instant::now();

    let response = build_request(client, method, url, headers, body)
        .send()
        .await?;
    let status_code = response.status().as_u16();

    let resp_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Check Content-Length before consuming the body
    let content_length = response.content_length();
    let content_type = resp_headers.get("content-type").cloned();

    if let Some(len) = content_length {
        if len > max_body_bytes as u64 {
            return Err(ExecuteError::ResponseTooLarge {
                content_length: Some(len),
                content_type,
                limit_bytes: max_body_bytes,
            });
        }
    }

    // Read body with size limit (handles chunked responses without Content-Length)
    let mut collected = Vec::new();
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        collected.extend_from_slice(&chunk);
        if collected.len() > max_body_bytes {
            return Err(ExecuteError::ResponseTooLarge {
                content_length,
                content_type,
                limit_bytes: max_body_bytes,
            });
        }
    }

    let body = String::from_utf8_lossy(&collected).into_owned();
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(ActionResult {
        status_code,
        headers: resp_headers,
        body,
        duration_ms,
        filtered_body: None,
    })
}

/// Execute an HTTP request and return the raw response for streaming.
/// The caller is responsible for consuming the response body.
pub async fn execute_streaming(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
    build_request(client, method, url, headers, body)
        .send()
        .await
}
