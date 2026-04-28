//! Search query metrics.

use metrics::counter;

/// `mode` ∈ {`vector`, `keyword`, `hybrid`}.
/// `status` ∈ {`ok`, `error`, `empty`}.
pub fn record_query(mode: &str, status: &str) {
    counter!(
        "overslash_search_queries_total",
        "mode" => mode.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);
}
