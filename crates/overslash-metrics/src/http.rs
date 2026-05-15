//! HTTP golden-signals middleware: request count, latency histogram, in-flight gauge.
//!
//! Uses `MatchedPath` so `path` labels are bounded by the route count, not the
//! cardinality of incoming URLs. Requests that don't match any route bucket
//! into the fixed `"_unmatched"` label — emitting the literal URI would let
//! scanners and bad clients explode our Prometheus cardinality.

use std::time::Instant;

use axum::{
    body::Body,
    extract::MatchedPath,
    http::{Request, Response},
    middleware::Next,
};
use metrics::{counter, gauge, histogram};

pub async fn middleware(
    matched_path: Option<MatchedPath>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let method = req.method().to_string();
    let path = matched_path.map_or_else(|| "_unmatched".to_string(), |mp| mp.as_str().to_string());

    // RAII guard: decrement the in-flight gauge on Drop. If the downstream
    // handler panics, the gauge still gets decremented as the future unwinds —
    // otherwise a single panic would permanently inflate the gauge.
    let _in_flight = InFlightGuard::new();
    let start = Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    counter!(
        "overslash_http_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status,
    )
    .increment(1);
    histogram!(
        "overslash_http_request_duration_seconds",
        "method" => method,
        "path" => path,
    )
    .record(duration);

    response
}

struct InFlightGuard;

impl InFlightGuard {
    fn new() -> Self {
        gauge!("overslash_http_requests_in_flight").increment(1);
        Self
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        gauge!("overslash_http_requests_in_flight").decrement(1);
    }
}
