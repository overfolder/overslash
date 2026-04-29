//! Secret-vault metrics. Never label by secret name — that's unbounded.

use metrics::counter;

/// `op` ∈ {`write`, `reveal`, `restore`, `rotate`, `delete`}.
/// `status` ∈ {`ok`, `denied`, `not_found`, `error`}.
pub fn record_op(op: &str, status: &str) {
    counter!(
        "overslash_secret_operations_total",
        "op" => op.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_op_does_not_panic() {
        record_op("write", "ok");
        record_op("reveal", "ok");
        record_op("delete", "not_found");
    }
}
