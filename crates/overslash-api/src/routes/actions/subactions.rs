//! Call-time `x-overslash-subactions`: rewriting a callable variant into its
//! parent, and classifying a parent call into variants.
//!
//! Both run in `/call` and `/validate` alike, at the same two points, so the
//! dry run and the real call cannot disagree on a key or a risk:
//!
//! 1. [`lower_direct_call`] right after argument validation — a call to
//!    `create_contact` becomes a call to `manage_crm_objects` with the
//!    variant's `transform` applied, and is validated again as the parent;
//! 2. [`classify`] once params are final — the parent's params are split into
//!    items and each is matched to a variant, which decides the description,
//!    risk, permission keys, disclosure and redaction of the call.
//!
//! Classification fails *coarse*, never open: a jq error, a timeout, or a call
//! with no items leaves the call exactly as an action without subactions
//! would be — the parent's key and the parent's risk.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;

use overslash_core::permissions::PermissionKey;
use overslash_core::subactions::{
    ClassifiedItem, describe_call, item_params, parse_classifier_output,
};
use overslash_core::types::{DisclosureField, Risk};

use crate::error::AppError;

use super::resolve_metadata::action_metadata;
use super::*;

/// Run one jq program over `input` off the async runtime, under the same
/// timeout every other template jq gets.
async fn run_jq(expr: String, input: String, timeout: Duration) -> Result<Vec<Value>, String> {
    let join = tokio::task::spawn_blocking(move || {
        crate::services::response_filter::run_jq_blocking(&expr, &input)
    });
    match tokio::time::timeout(timeout, join).await {
        Ok(Ok(Ok((out, _)))) => Ok(out),
        Ok(Ok(Err(crate::services::response_filter::JqErr::RuntimeError(e)))) => Err(e),
        Ok(Ok(Err(_))) => Err("jq evaluation failed".into()),
        Ok(Err(_)) => Err("jq task panicked".into()),
        Err(_) => Err("jq timed out".into()),
    }
}

/// When the called action is a callable variant, rewrite the request into a
/// call to its parent and re-describe it as the parent. Returns the variant's
/// key, which [`classify`] then holds the call to.
///
/// `req.params` must already be validated against the variant's own schema;
/// the caller validates them again, as the parent's, afterwards.
pub(super) async fn lower_direct_call(
    timeout: Duration,
    pre_meta: &mut ActionMetadata,
    mode_c: Option<&ResolvedModeC>,
    req: &mut CallRequest,
) -> Result<Option<String>, AppError> {
    let Some(of) = pre_meta.subaction_of.clone() else {
        return Ok(None);
    };
    let mode_c = mode_c.ok_or_else(|| {
        AppError::Internal("callable subaction without a resolved service".into())
    })?;
    let transform = mode_c
        .svc
        .actions
        .get(&of.parent)
        .and_then(|p| p.subactions.as_ref())
        .and_then(|s| s.variant(&of.variant))
        .and_then(|v| v.transform.clone())
        .ok_or_else(|| {
            AppError::Internal(format!(
                "callable subaction `{}` lost its parent `{}`",
                of.variant, of.parent
            ))
        })?;

    let input = serde_json::to_string(&req.params).unwrap_or_else(|_| "{}".into());
    let rewritten = match run_jq(transform, input, timeout).await {
        Ok(mut out) if out.len() == 1 && out[0].is_object() => out.remove(0),
        outcome => {
            // The jq message can quote the caller's arguments; it goes to the
            // caller (whose arguments they are) but never to the log.
            let why = match outcome {
                Err(e) => e,
                Ok(out) => format!("expected one object, got {} value(s)", out.len()),
            };
            tracing::warn!(
                action = %of.variant,
                "subaction transform did not produce the parent's params"
            );
            return Err(AppError::BadRequest(format!(
                "action '{}' could not build its call to '{}' from these arguments: {why}",
                of.variant, of.parent
            )));
        }
    };
    let Value::Object(map) = rewritten else {
        unreachable!("checked is_object above")
    };
    req.params = map.into_iter().collect();
    req.action = Some(of.parent.clone());
    let service_key = req.service.clone().unwrap_or_default();
    *pre_meta = action_metadata(&mode_c.svc, &mode_c.instance, &service_key, &of.parent, req)?;
    Ok(Some(of.variant))
}

/// What classification decided about one call.
pub(super) struct SubactionOutcome {
    /// Without the ` (Service)` suffix.
    pub(super) description: String,
    pub(super) risk: Risk,
    /// Keys for the claimed items. When [`unclaimed`](Self::unclaimed) is set
    /// the parent's own keys must be required beside these.
    pub(super) keys: Vec<PermissionKey>,
    pub(super) unclaimed: bool,
    /// Matched variant keys, in declaration order.
    pub(super) variants: Vec<String>,
    pub(super) disclose: Vec<DisclosureField>,
    pub(super) redact: Vec<String>,
    pub(super) timeout_ms: Option<u64>,
}

/// Classify a call to an action with subactions. `None` when the action has
/// none, or when classification failed or found no items — the call then
/// proceeds exactly as the parent. `direct` is the variant a callable call was
/// lowered from; such a call must classify entirely as that variant, or it is
/// refused: its keys would otherwise be minted from something other than what
/// the caller asked for.
pub(super) async fn classify(
    timeout: Duration,
    pre_meta: &ActionMetadata,
    params: &HashMap<String, Value>,
    resolved: &HashMap<String, String>,
    direct: Option<&str>,
) -> Result<Option<SubactionOutcome>, AppError> {
    let Some(ctx) = pre_meta.subactions.as_ref() else {
        return Ok(None);
    };
    let Some(scope) = pre_meta.service_scope.as_ref() else {
        return Ok(None);
    };
    let spec = &ctx.spec;

    let input = serde_json::to_string(params).unwrap_or_else(|_| "{}".into());
    let items: Option<Vec<ClassifiedItem>> = match run_jq(spec.classifier_program(), input, timeout)
        .await
    {
        Ok(out) if out.len() == 1 => match parse_classifier_output(spec, &out[0]) {
            Ok(items) => Some(items),
            Err(e) => {
                tracing::warn!(service = %scope.service_key, action = %scope.action_key, "subaction classifier output malformed: {e}");
                None
            }
        },
        _ => {
            tracing::warn!(
                service = %scope.service_key,
                action = %scope.action_key,
                "subaction classifier failed; the call is gated as the parent"
            );
            None
        }
    };
    let items = items.filter(|i| !i.is_empty());

    if let Some(variant) = direct {
        let all_this = items.as_ref().is_some_and(|items| {
            items
                .iter()
                .all(|i| i.variant.is_some_and(|n| spec.variants[n].key == variant))
        });
        if !all_this {
            return Err(AppError::BadRequest(format!(
                "action '{variant}' rewrote these arguments into a call that does not \
                 classify as '{variant}'; the template's transform and match disagree"
            )));
        }
    }
    let Some(items) = items else {
        return Ok(None);
    };

    let parent_label = overslash_core::description::interpolate_description_with_resolved(
        &ctx.label_template,
        params,
        resolved,
    );
    let description = describe_call(spec, &items, &parent_label, params, resolved);

    let unclaimed = items.iter().any(|i| i.variant.is_none());
    let base = pre_meta.risk.map(|r| r.base_risk()).unwrap_or(Risk::Write);
    let mut risk = if unclaimed { base } else { Risk::Read };
    let mut keys: Vec<PermissionKey> = Vec::new();
    let mut variants: Vec<String> = Vec::new();
    let mut disclose: Vec<DisclosureField> = Vec::new();
    let mut redact: Vec<String> = Vec::new();
    let mut timeout_ms: Option<u64> = None;

    for (n, v) in spec.variants.iter().enumerate() {
        let group: Vec<&ClassifiedItem> = items.iter().filter(|i| i.variant == Some(n)).collect();
        if group.is_empty() {
            continue;
        }
        variants.push(v.key.clone());
        risk = risk.max_severity(v.risk);
        let perm_action = format!("{}/{}", scope.action_key, v.key);
        for item in &group {
            let scope_values = resolve_scope_values(
                &v.scope_param,
                &item_params(&item.item),
                timeout,
                &scope.service_key,
                &perm_action,
            )
            .await;
            for k in
                PermissionKey::from_service_action(&scope.service_key, &perm_action, &scope_values)
            {
                if !keys.contains(&k) {
                    keys.push(k);
                }
            }
        }
        if !v.disclose.is_empty() {
            // The variant's filters address `.items` — its own items. They are
            // bound as a literal rather than added to the shared projection,
            // because the projection is what gets persisted, and a copy of the
            // arguments there would sit beside the redacted original unredacted.
            let items_json: Vec<&serde_json::Map<String, Value>> =
                group.iter().map(|i| &i.item).collect();
            let literal = serde_json::to_string(&items_json).unwrap_or_else(|_| "[]".into());
            for field in &v.disclose {
                disclose.push(DisclosureField {
                    filter: format!(
                        "({literal}) as $__items | .items = $__items | ({})",
                        field.filter
                    ),
                    ..field.clone()
                });
            }
        }
        for r in &v.redact {
            if !redact.contains(r) {
                redact.push(r.clone());
            }
        }
        timeout_ms = match (timeout_ms, v.timeout_ms) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }

    Ok(Some(SubactionOutcome {
        description: format!("{description} ({})", ctx.service_display_name),
        risk,
        keys,
        unclaimed,
        variants,
        disclose,
        redact,
        timeout_ms,
    }))
}

impl SubactionOutcome {
    /// Fold the outcome into the resolved call so everything downstream —
    /// approval, audit, tags, disclosure — reads the classified call.
    pub(super) fn apply(&self, meta: &mut ResolvedMeta) {
        meta.description = Some(self.description.clone());
        meta.risk = Some(self.risk.into());
        meta.disclose.extend(self.disclose.iter().cloned());
        for r in &self.redact {
            if !meta.redact.contains(r) {
                meta.redact.push(r.clone());
            }
        }
        if let Some(t) = self.timeout_ms {
            meta.action_timeout_ms = Some(meta.action_timeout_ms.map_or(t, |a| a.max(t)));
        }
        meta.subactions = self.variants.clone();
    }

    /// The call's permission keys: the classified items' keys, plus the
    /// parent's own when any item went unclaimed.
    pub(super) fn merge_keys(&self, parent_keys: Vec<PermissionKey>) -> Vec<PermissionKey> {
        let mut out = if self.unclaimed {
            parent_keys
        } else {
            Vec::new()
        };
        for k in &self.keys {
            if !out.contains(k) {
                out.push(k.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated classifier must run on the real jq engine — the core
    /// crate only builds the string.
    #[tokio::test]
    async fn the_classifier_program_runs_on_jaq() {
        let spec: overslash_core::types::SubactionSpec = serde_json::from_value(serde_json::json!({
            "each": "(.createRequest.objects[]? | . + {op: \"create\"}), (.updateRequest.objects[]? | . + {op: \"update\"})",
            "variants": [
                {"key": "create_contact", "match": ".op == \"create\" and .objectType == \"contacts\"",
                 "description": "", "risk": "write", "vars": {"label": ".properties.email"}},
                {"key": "update_deal", "match": ".op == \"update\" and .objectType == \"deals\"",
                 "description": "", "risk": "write", "vars": {"label": ".properties.dealname // (.objectId | tostring)"}},
                {"key": "never", "match": "empty", "description": "", "risk": "read"}
            ]
        }))
        .unwrap();
        let params = serde_json::json!({
            "createRequest": {"objects": [
                {"objectType": "contacts", "properties": {"email": "jane@acme.com"}},
                {"objectType": "notes", "properties": {}}
            ]},
            "updateRequest": {"objects": [{"objectType": "deals", "objectId": 42, "properties": {}}]}
        });
        let out = run_jq(
            spec.classifier_program(),
            params.to_string(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let items = parse_classifier_output(&spec, &out[0]).unwrap();
        assert_eq!(
            items.len(),
            3,
            "an item no predicate claims is kept, not dropped"
        );
        assert_eq!(items[0].variant, Some(0));
        assert_eq!(items[0].item["label"], serde_json::json!("jane@acme.com"));
        assert_eq!(items[1].variant, None);
        assert_eq!(items[2].variant, Some(1));
        assert_eq!(items[2].item["label"], serde_json::json!("42"));
    }

    #[tokio::test]
    async fn without_each_the_whole_call_is_one_item() {
        let spec: overslash_core::types::SubactionSpec =
            serde_json::from_value(serde_json::json!({
                "variants": [{"key": "get_contacts", "match": ".objectType == \"contacts\"",
                              "description": "", "risk": "read"}]
            }))
            .unwrap();
        let out = run_jq(
            spec.classifier_program(),
            r#"{"objectType":"contacts","objectIds":[1]}"#.into(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let items = parse_classifier_output(&spec, &out[0]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].variant, Some(0));
        assert_eq!(items[0].item["objectIds"], serde_json::json!([1]));
    }

    /// A predicate that errors fails the whole program: the caller then gates
    /// the call as the parent rather than dropping the item.
    #[tokio::test]
    async fn a_failing_predicate_fails_the_program() {
        let spec: overslash_core::types::SubactionSpec = serde_json::from_value(serde_json::json!({
            "variants": [{"key": "x", "match": "error(\"boom\")", "description": "", "risk": "read"}]
        }))
        .unwrap();
        let out = run_jq(
            spec.classifier_program(),
            "{}".into(),
            Duration::from_secs(5),
        )
        .await;
        assert!(out.is_err());
    }
}
