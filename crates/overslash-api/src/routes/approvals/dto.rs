//! Wire-DTO helpers for the approval routes: runtime / status probing,
//! truncation, and risk-class derivation.

use super::*;

/// Probe a stored execution `result` JSONB for the runtime tag. MCP envelopes
/// carry `{ "runtime": "mcp", ... }` from `mcp_caller`; HTTP envelopes don't
/// declare a runtime field, so we fall back to a `status_code` presence
/// check. Anything else (truncation sentinels, unknown shapes) returns None.
pub(super) fn extract_runtime(v: &serde_json::Value) -> Option<String> {
    if let Some(rt) = v.get("runtime").and_then(|x| x.as_str()) {
        return Some(rt.to_string());
    }
    if v.get("status_code").is_some() {
        return Some("http".to_string());
    }
    None
}

pub(super) fn extract_http_status_code(v: &serde_json::Value) -> Option<u16> {
    v.get("status_code")
        .and_then(|x| x.as_u64())
        .and_then(|n| u16::try_from(n).ok())
}

/// Truncate a JSON value's string representation to at most
/// `MAX_EXECUTION_RESULT_BYTES`. If the full serialization is under the cap we
/// return the value as-is; over the cap we swap in a compact sentinel so the
/// dashboard can render a "truncated" banner without parsing a gigantic body.
pub(super) fn truncate_json_value(v: serde_json::Value) -> serde_json::Value {
    match serde_json::to_string(&v) {
        Ok(s) if s.len() > MAX_EXECUTION_RESULT_BYTES => serde_json::json!({
            "truncated": true,
            "size_bytes": s.len(),
            "limit_bytes": MAX_EXECUTION_RESULT_BYTES,
        }),
        _ => v,
    }
}

/// Derive the dashboard-facing risk class (`"low" | "med" | "high"`) for an
/// approval by looking up the first derived key in the live service registry.
/// Misses fall back to `"med"` — a deliberately cautious default so the UI
/// errs on the side of "review carefully" rather than "low risk" when the
/// service template has been removed or renamed since the approval row was
/// written.
pub(super) fn derive_risk_class(registry: &ServiceRegistry, derived_keys: &[DerivedKey]) -> String {
    let Some(first) = derived_keys.first() else {
        return "med".to_string();
    };
    let risk = registry
        .get(&first.service)
        .and_then(|svc| svc.actions.get(&first.action))
        .map(|action| action.risk.display_risk());
    risk_class(risk)
}

/// Map an action's risk level to the dashboard-facing class string
/// (`"low" | "med" | "high"`). `None` → `"med"`, the same cautious default
/// `derive_risk_class` falls back to. Shared so the inline `pending_approval`
/// envelope (built in `routes::actions`) and the `GET /v1/approvals/{id}` read
/// path produce identical risk strings for the same action.
pub(crate) fn risk_class(risk: Option<Risk>) -> String {
    match risk {
        Some(Risk::Read) => "low",
        Some(Risk::Write) => "med",
        Some(Risk::Delete) => "high",
        None => "med",
    }
    .to_string()
}

/// Pretty-print a stored `action_detail` JSONB blob for the wire, truncating
/// at `MAX_ACTION_DETAIL_BYTES` on a UTF-8 boundary. Returns
/// `(rendered, truncated, full_size_bytes)` — `(None, false, 0)` when there
/// is no detail. Shared between `ApprovalResponse::from_row` and the inline
/// `pending_approval` envelope so the two can't drift on truncation rules.
pub(crate) fn render_action_detail(
    detail: Option<&serde_json::Value>,
) -> (Option<String>, bool, usize) {
    match detail.and_then(|v| serde_json::to_string_pretty(v).ok()) {
        Some(full) => {
            let size = full.len();
            if size > MAX_ACTION_DETAIL_BYTES {
                let trimmed = truncate_utf8(&full, MAX_ACTION_DETAIL_BYTES).to_string();
                (Some(trimmed), true, size)
            } else {
                (Some(full), false, size)
            }
        }
        None => (None, false, 0),
    }
}

/// Truncate a UTF-8 string to at most `max` bytes, walking backward from the
/// boundary so multibyte characters are never split.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut idx = max;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

#[cfg(test)]
mod risk_tests {
    use super::*;
    use overslash_core::permissions::DerivedKey;
    use overslash_core::types::service::{Runtime, ServiceAction, ServiceDefinition};
    use std::collections::HashMap;

    fn registry_with(key: &str, action: &str, risk: Risk) -> ServiceRegistry {
        let mut actions = HashMap::new();
        actions.insert(
            action.into(),
            ServiceAction {
                timeout_ms: None,
                method: "GET".into(),
                path: "/".into(),
                description: String::new(),
                summary: None,
                risk: risk.into(),
                response_type: None,
                params: HashMap::new(),
                scope_param: Default::default(),
                required_scopes: vec![],
                permission: None,
                disclose: vec![],
                redact: vec![],
                mcp_tool: None,
                output_schema: None,
                disabled: false,
                request_body: None,
                download: None,
            },
        );
        let mut registry = ServiceRegistry::default();
        registry.insert(ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: key.into(),
            display_name: key.into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            icon: None,
            auth: vec![],
            actions,
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        });
        registry
    }

    fn dk(service: &str, action: &str) -> DerivedKey {
        overslash_core::permissions::parse_derived_key(&format!("{service}:{action}:*"))
    }

    #[test]
    fn risk_read_maps_low() {
        let reg = registry_with("github", "list_repos", Risk::Read);
        let keys = vec![dk("github", "list_repos")];
        assert_eq!(derive_risk_class(&reg, &keys), "low");
    }

    #[test]
    fn risk_write_maps_med() {
        let reg = registry_with("github", "create_pr", Risk::Write);
        let keys = vec![dk("github", "create_pr")];
        assert_eq!(derive_risk_class(&reg, &keys), "med");
    }

    #[test]
    fn risk_delete_maps_high() {
        let reg = registry_with("postgres", "drop_database", Risk::Delete);
        let keys = vec![dk("postgres", "drop_database")];
        assert_eq!(derive_risk_class(&reg, &keys), "high");
    }

    #[test]
    fn missing_service_falls_back_to_med() {
        let reg = ServiceRegistry::default();
        let keys = vec![dk("ghost", "vanish")];
        assert_eq!(derive_risk_class(&reg, &keys), "med");
    }

    #[test]
    fn missing_action_falls_back_to_med() {
        let reg = registry_with("github", "list_repos", Risk::Read);
        let keys = vec![dk("github", "create_pr")];
        assert_eq!(derive_risk_class(&reg, &keys), "med");
    }

    #[test]
    fn empty_derived_keys_falls_back_to_med() {
        let reg = ServiceRegistry::default();
        assert_eq!(derive_risk_class(&reg, &[]), "med");
    }
}
