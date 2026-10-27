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
    /// What the description is rendered from, once the resolvers' display
    /// names exist — classification itself runs before them.
    items: Vec<ClassifiedItem>,
    spec: overslash_core::types::SubactionSpec,
    label_template: String,
    service_display_name: String,
    pub(super) risk: Risk,
    /// OAuth scopes the matched variants add to the parent's. Checked by
    /// [`check_scopes`](Self::check_scopes) against the instance's connection.
    pub(super) required_scopes: Vec<String>,
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

    let unclaimed = items.iter().any(|i| i.variant.is_none());
    let base = pre_meta.risk.map(|r| r.base_risk()).unwrap_or(Risk::Write);
    let mut risk = if unclaimed { base } else { Risk::Read };
    let mut keys: Vec<PermissionKey> = Vec::new();
    let mut variants: Vec<String> = Vec::new();
    let mut disclose: Vec<DisclosureField> = Vec::new();
    let mut redact: Vec<String> = Vec::new();
    let mut timeout_ms: Option<u64> = None;
    let mut required_scopes: Vec<String> = Vec::new();

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
        for sc in &v.required_scopes {
            if !required_scopes.contains(sc) {
                required_scopes.push(sc.clone());
            }
        }
        timeout_ms = match (timeout_ms, v.timeout_ms) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }

    Ok(Some(SubactionOutcome {
        items,
        spec: spec.clone(),
        label_template: ctx.label_template.clone(),
        service_display_name: ctx.service_display_name.clone(),
        risk,
        required_scopes,
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
    pub(super) fn apply(&self, meta: &mut ResolvedMeta, params: &HashMap<String, Value>) {
        meta.description = Some(self.describe(params, &meta.resolved));
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

    /// The call's description, with the ` (Service)` suffix every action
    /// description carries. `resolved` is empty on `/validate`, which runs no
    /// resolvers (D55); keys and risk never read it.
    pub(super) fn describe(
        &self,
        params: &HashMap<String, Value>,
        resolved: &HashMap<String, String>,
    ) -> String {
        let parent_label = overslash_core::description::interpolate_description_with_resolved(
            &self.label_template,
            params,
            resolved,
        );
        let description = describe_call(&self.spec, &self.items, &parent_label, params, resolved);
        format!("{description} ({})", self.service_display_name)
    }

    /// The scope gate for the variants' own `required_scopes` — the same
    /// fail-fast `missing_scopes` check the parent's scopes get in
    /// `resolve_request`, which only ever sees the parent action. Runs before
    /// resolution consumes the instance.
    pub(super) async fn check_scopes(
        &self,
        state: &crate::AppState,
        scope: &overslash_db::scopes::OrgScope,
        owner_identity_id: uuid::Uuid,
        mode_c: Option<&ResolvedModeC>,
        return_url: Option<&str>,
    ) -> Result<(), AppError> {
        let Some(mode_c) = mode_c else {
            return Ok(());
        };
        if self.required_scopes.is_empty() {
            return Ok(());
        }
        let synthetic = overslash_core::types::ServiceAction {
            required_scopes: self.required_scopes.clone(),
            ..Default::default()
        };
        let hint = crate::services::platform_connections::parse_return_url(return_url)?;
        super::auth_scopes::check_required_scopes(
            state,
            scope,
            owner_identity_id,
            Some(&mode_c.instance),
            &mode_c.svc,
            &synthetic,
            hint.as_deref(),
        )
        .await
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

    use serde_json::json;

    const T: Duration = Duration::from_secs(5);

    /// A CRM-shaped parent: two write variants scoped by label, one delete
    /// variant with its own disclosure, redaction, scope and timeout.
    fn crm_spec() -> overslash_core::types::SubactionSpec {
        serde_json::from_value(json!({
            "each": ".objects[]",
            "variants": [
                {"key": "create_contact", "match": ".objectType == \"contacts\"",
                 "description": "", "risk": "write", "verb": "create",
                 "phrase": "contact '{item.label}'", "scope_param": "label",
                 "vars": {"label": ".email"}, "redact": ["$.objects"],
                 "required_scopes": ["crm.contacts"], "timeout_ms": 1000},
                {"key": "purge_deal", "match": ".objectType == \"deals\"",
                 "description": "Purge deals", "risk": "delete",
                 "disclose": [{"label": "Deals", "filter": "[.items[].id] | join(\", \")"}],
                 "redact": ["$.objects", "$.reason"],
                 "required_scopes": ["crm.contacts", "crm.admin"], "timeout_ms": 9000}
            ]
        }))
        .unwrap()
    }

    fn meta(spec: Option<overslash_core::types::SubactionSpec>) -> ActionMetadata {
        ActionMetadata {
            validation_params: HashMap::new(),
            additional_properties: false,
            service_scope: Some(ServiceScope {
                service_key: "crm".into(),
                action_key: "manage".into(),
                scope_param: Default::default(),
                http_verb: None,
            }),
            risk: Some(Risk::Write.into()),
            raw_method: String::new(),
            raw_url: String::new(),
            needs_gate: true,
            subactions: spec.map(|spec| SubactionContext {
                spec,
                label_template: "Manage CRM records".into(),
                service_display_name: "CRM".into(),
            }),
            subaction_of: None,
        }
    }

    fn params(v: Value) -> HashMap<String, Value> {
        serde_json::from_value(v).unwrap()
    }

    fn key_strings(keys: &[PermissionKey]) -> Vec<&str> {
        keys.iter().map(|k| k.0.as_str()).collect()
    }

    #[tokio::test]
    async fn a_mixed_batch_folds_every_matched_variants_controls() {
        let m = meta(Some(crm_spec()));
        let p = params(json!({"objects": [
            {"objectType": "contacts", "email": "a@x.com"},
            {"objectType": "contacts", "email": "a@x.com"},
            {"objectType": "deals", "id": "d1"},
            {"objectType": "deals", "id": "d2"}
        ]}));
        let out = classify(T, &m, &p, None).await.unwrap().unwrap();

        assert_eq!(out.variants, ["create_contact", "purge_deal"]);
        assert_eq!(out.risk, Risk::Delete, "the most severe variant wins");
        assert!(!out.unclaimed);
        assert_eq!(
            key_strings(&out.keys),
            [
                "crm:manage/create_contact:label=a@x.com",
                "crm:manage/purge_deal:*"
            ],
            "one key per distinct scope value, however many items carry it"
        );
        assert_eq!(out.redact, ["$.objects", "$.reason"]);
        assert_eq!(out.required_scopes, ["crm.contacts", "crm.admin"]);
        assert_eq!(out.timeout_ms, Some(9000));

        // The variant's filter reads its own items, bound as a literal.
        assert_eq!(out.disclose.len(), 1);
        let filter = &out.disclose[0].filter;
        assert!(
            filter.contains("as $__items | .items = $__items"),
            "{filter}"
        );
        let shown = run_jq(filter.clone(), "{}".into(), T).await.unwrap();
        assert_eq!(shown, [json!("d1, d2")]);

        assert_eq!(
            out.describe(&p, &HashMap::new()),
            "Create contact 'a@x.com' and contact 'a@x.com'; Purge deals (CRM)"
        );
        let parent = vec![PermissionKey("crm:manage:*".into())];
        assert_eq!(
            key_strings(&out.merge_keys(parent)),
            [
                "crm:manage/create_contact:label=a@x.com",
                "crm:manage/purge_deal:*"
            ],
            "a fully claimed call does not need the parent's key"
        );
    }

    #[tokio::test]
    async fn an_unclaimed_item_keeps_the_parent_key_and_risk() {
        let mut m = meta(Some(crm_spec()));
        m.risk = Some(Risk::Delete.into());
        let p = params(json!({"objects": [
            {"objectType": "contacts", "email": "a@x.com"},
            {"objectType": "notes"}
        ]}));
        let out = classify(T, &m, &p, None).await.unwrap().unwrap();
        assert!(out.unclaimed);
        assert_eq!(
            out.risk,
            Risk::Delete,
            "the parent's risk floors an unclaimed call"
        );
        assert_eq!(
            key_strings(&out.merge_keys(vec![
                PermissionKey("crm:manage:*".into()),
                PermissionKey("crm:manage/create_contact:label=a@x.com".into()),
            ])),
            ["crm:manage:*", "crm:manage/create_contact:label=a@x.com"],
            "the parent's keys first, without repeats"
        );
        assert_eq!(
            out.describe(&p, &HashMap::new()),
            "Create contact 'a@x.com'; Manage CRM records (CRM)"
        );
    }

    #[tokio::test]
    async fn without_a_declared_risk_an_unclaimed_item_is_a_write() {
        let mut m = meta(Some(crm_spec()));
        m.risk = None;
        let out = classify(
            T,
            &m,
            &params(json!({"objects": [{"objectType": "notes"}]})),
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(out.risk, Risk::Write);
    }

    #[tokio::test]
    async fn nothing_to_classify_leaves_the_call_as_the_parent() {
        let p = params(json!({"objects": []}));
        assert!(classify(T, &meta(None), &p, None).await.unwrap().is_none());

        let mut unscoped = meta(Some(crm_spec()));
        unscoped.service_scope = None;
        assert!(classify(T, &unscoped, &p, None).await.unwrap().is_none());

        let m = meta(Some(crm_spec()));
        assert!(
            classify(T, &m, &p, None).await.unwrap().is_none(),
            "a call with no items is gated as the parent"
        );
        // `each` over a non-array errors: coarse, not refused.
        let bad = params(json!({"objects": 5}));
        assert!(classify(T, &m, &bad, None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_direct_call_must_classify_entirely_as_its_variant() {
        let m = meta(Some(crm_spec()));
        let contact = params(json!({"objects": [{"objectType": "contacts", "email": "a@x.com"}]}));
        let out = classify(T, &m, &contact, Some("create_contact"))
            .await
            .unwrap();
        assert_eq!(out.unwrap().variants, ["create_contact"]);

        for p in [
            json!({"objects": [{"objectType": "contacts", "email": "a@x.com"}, {"objectType": "deals"}]}),
            json!({"objects": [{"objectType": "notes"}]}),
            json!({"objects": []}),
            json!({"objects": 5}),
        ] {
            let err = classify(T, &m, &params(p.clone()), Some("create_contact"))
                .await
                .err()
                .unwrap_or_else(|| panic!("{p} must be refused"));
            assert!(
                matches!(&err, AppError::BadRequest(msg) if msg.contains("does not classify as 'create_contact'")),
                "{p}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_call_without_subaction_of_is_not_lowered() {
        let mut m = meta(None);
        let mut req: CallRequest = serde_json::from_value(json!({
            "service": "crm", "action": "manage", "params": {"a": 1}
        }))
        .unwrap();
        assert_eq!(
            lower_direct_call(T, &mut m, None, &mut req).await.unwrap(),
            None
        );
        assert_eq!(req.action.as_deref(), Some("manage"));

        m.subaction_of = Some(overslash_core::types::SubactionRef {
            parent: "manage".into(),
            variant: "create_contact".into(),
        });
        assert!(
            matches!(
                lower_direct_call(T, &mut m, None, &mut req).await,
                Err(AppError::Internal(_))
            ),
            "a callable variant always comes with its resolved service"
        );
    }

    #[tokio::test]
    async fn jq_failures_are_reported_not_raised() {
        assert!(
            run_jq("error(\"boom\")".into(), "{}".into(), T)
                .await
                .unwrap_err()
                .contains("boom")
        );
        assert_eq!(
            run_jq(".".into(), "not json".into(), T).await.unwrap_err(),
            "jq evaluation failed",
            "anything but a runtime error is summarized, not echoed"
        );
        assert_eq!(
            // Finite, so the abandoned blocking thread winds down on its own.
            run_jq(
                "reduce range(1e6) as $i (0; . + 1)".into(),
                "{}".into(),
                Duration::ZERO
            )
            .await
            .unwrap_err(),
            "jq timed out"
        );
    }
}
