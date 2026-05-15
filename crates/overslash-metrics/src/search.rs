//! Search query metrics.

use metrics::counter;

/// `mode` ∈ {`vector`, `keyword`, `hybrid`, `browse`}.
/// `status` ∈ {`ok`, `error`, `empty`}.
pub fn record_query(mode: &str, status: &str) {
    counter!(
        "overslash_search_queries_total",
        "mode" => mode.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_query_does_not_panic() {
        record_query("hybrid", "ok");
        record_query("keyword", "ok");
        record_query("browse", "ok");
    }
}
