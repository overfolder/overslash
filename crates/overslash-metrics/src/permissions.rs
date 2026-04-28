//! Permission-check metrics. The two layers (group ceiling vs identity rule)
//! are emitted separately so dashboards can show which layer denies most.

use metrics::counter;

/// `decision` ∈ {`allow`, `deny`, `bubble`}.
/// `layer` ∈ {`group_ceiling`, `identity_rule`, `inherited`}.
pub fn record_check(decision: &str, layer: &str) {
    counter!(
        "overslash_permission_checks_total",
        "decision" => decision.to_string(),
        "layer" => layer.to_string(),
    )
    .increment(1);
}
