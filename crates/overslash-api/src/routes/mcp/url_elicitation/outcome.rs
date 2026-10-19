//! What the agent reads once a hand-off ends.
//!
//! A completed setup or connect link is answered with what it produced, never
//! with the original result: that result carries the link and an
//! `action_description` telling the agent to hand it over, and an agent given
//! both re-shares a link its user already finished. A hand-off that did not
//! complete keeps the original body (its link may still be wanted), with a
//! note saying how it ended and what to do next.

use super::*;

/// The field on every answer a hand-off shaped.
const NOTE_FIELD: &str = "url_elicitation";

const COMPLETED_NEXT: &str = "The user already finished this in their client. Do not share \
     the link again. Continue with the original task.";

const UNBOUND_NEXT: &str = " No service is pinned to this connection, and it is not the \
     default for its provider: bind it to a service before expecting that service's calls \
     to use it.";

impl Stopped {
    /// What the agent should do about it. An approval link is its own case:
    /// dismissing it decides nothing, and no service is waiting on a
    /// connection.
    fn next(&self, then: Then) -> &'static str {
        if then == Then::CallApproval {
            return match self {
                Stopped::Declined(_) | Stopped::Cancelled => {
                    "The user dismissed the approval link without deciding: the approval is \
                     still pending, not denied. Ask before offering the link again."
                }
                Stopped::TimedOut => {
                    "The approval is still pending at this link. Do not re-share it on your \
                     own; resume it later with overslash_call and its approval_id to see \
                     whether it was decided."
                }
                Stopped::Failed(_) => {
                    "The approval could not be read back. Call the original action again if \
                     it is still needed."
                }
            };
        }
        match self {
            Stopped::Declined(_) | Stopped::Cancelled => {
                "The user saw this link and refused it. Ask before offering it again."
            }
            Stopped::TimedOut => {
                "The link is still valid. Check overslash_auth service_status first, and only \
                 re-share the link if the service is still not connected."
            }
            Stopped::Failed(_) => {
                "The browser step did not complete. Check overslash_auth service_status first; \
                 if the service is still not connected, request a fresh link rather than \
                 re-sharing this one."
            }
        }
    }
}

/// The original body, with a note saying how the hand-off ended.
pub(super) fn noted(body: &Value, stopped: &Stopped, then: Then) -> Value {
    let mut note = json!({ "status": stopped.note(), "next": stopped.next(then) });
    if let Some(reason) = stopped.reason() {
        note["reason"] = json!(reason);
    }
    let mut map = match body {
        Value::Object(map) => map.clone(),
        other => {
            let mut m = serde_json::Map::new();
            m.insert("result".into(), other.clone());
            m
        }
    };
    map.insert(NOTE_FIELD.into(), note);
    Value::Object(map)
}

/// Every hand-off of a `Report` plan completed: say what they produced.
/// Each lookup is best-effort — one that fails leaves its field out rather
/// than failing a call whose setup did, in fact, finish.
pub(super) async fn completed(ctx: &Ctx, plan: &Plan) -> Value {
    let mut connections = Vec::new();
    let mut secrets = Vec::new();
    for handoff in &plan.handoffs {
        match &handoff.watch {
            Watch::OauthFlow { id } => {
                if let Some(c) = connection(ctx, id).await {
                    connections.push(c);
                }
            }
            Watch::SecretRequest { id } => {
                let mut s = json!({ "request_id": id });
                // `request_secret` does not echo the vault name; its params
                // carry it. A slot's `credential_key` is a different thing —
                // the template's slot, not the vault name — reported apart.
                let name = request_field(&plan.fallback, id, "secret_name").or_else(|| {
                    ctx.args
                        .pointer("/params/secret_name")
                        .and_then(Value::as_str)
                });
                if let Some(name) = name {
                    s["secret_name"] = json!(name);
                }
                if let Some(key) = request_field(&plan.fallback, id, "credential_key") {
                    s["credential_key"] = json!(key);
                }
                secrets.push(s);
            }
            Watch::Approval { .. } => {}
        }
    }

    let mut next = COMPLETED_NEXT.to_string();
    // An unpinned instance on `use_default_connection` follows the default,
    // so a default connection is in use even with nothing pinned to it. An
    // unread `is_default` (the lookup failed) is not evidence of either.
    if connections.iter().any(|c| {
        c["bound_services"].as_array().is_some_and(Vec::is_empty) && c["is_default"] == false
    }) {
        next.push_str(UNBOUND_NEXT);
    }
    let mut note = json!({ "status": "completed" });
    if !connections.is_empty() {
        note["connections"] = json!(connections);
    }
    if !secrets.is_empty() {
        note["secrets"] = json!(secrets);
    }
    if let Some(service) = service_after(ctx, plan).await {
        note["service"] = service;
    }
    note["next"] = json!(next);
    json!({ NOTE_FIELD: note })
}

/// The connection a completed flow produced. Only for the caller that
/// started the flow, and read as its owner: the connection belongs to the
/// flow's `identity_id` (the owner user, D22), which for an agent caller is
/// not the caller itself — so `GET /v1/connections/{id}` would 404 it.
async fn connection(ctx: &Ctx, flow_id: &str) -> Option<Value> {
    let db = ctx.state.db(&ctx.ext);
    let flow = overslash_db::repos::oauth_connection_flow::completion(db, flow_id)
        .await
        .inspect_err(|e| tracing::warn!(flow_id, "read completed oauth flow failed: {e}"))
        .ok()??;
    if flow.org_id != ctx.auth.org_id || Some(flow.actor_identity_id) != ctx.auth.identity_id {
        return None;
    }
    let id = flow.connection_id?;
    let mut out = json!({ "connection_id": id });
    let pool = ctx.state.db_pool(&ctx.ext);
    let owner = overslash_db::UserScope::new(flow.org_id, flow.identity_id, pool.clone());
    match owner.get_my_connection(id).await {
        Ok(Some(conn)) => {
            out["provider_key"] = json!(conn.provider_key);
            out["is_default"] = json!(conn.is_default);
            if let Some(email) = conn.account_email {
                out["account_email"] = json!(email);
            }
            if let Some(scopes) = conn.scopes {
                out["scopes"] = json!(scopes);
            }
        }
        Ok(None) => return Some(out),
        Err(e) => tracing::warn!(%id, "read produced connection failed: {e}"),
    }
    let org = overslash_db::OrgScope::new(flow.org_id, pool);
    match org.connection_bound_instances(id).await {
        Ok(bound) => {
            let bound: Vec<Value> = bound
                .into_iter()
                .map(|(name, status)| json!({ "name": name, "status": status }))
                .collect();
            out["bound_services"] = json!(bound);
        }
        Err(e) => tracing::warn!(%id, "read services bound to connection failed: {e}"),
    }
    Some(out)
}

/// For `create_service`, or an `update_service` that switched auth mode and
/// so minted a fresh handshake, the instance, re-read now that its setup is
/// done: the `credentials_status` in the original result predates it.
async fn service_after(ctx: &Ctx, plan: &Plan) -> Option<Value> {
    let action = ctx.args.get("action").and_then(Value::as_str);
    if !matches!(action, Some("create_service" | "update_service")) {
        return None;
    }
    let name = plan
        .fallback
        .pointer("/result/body/name")
        .and_then(Value::as_str)?;
    match forward(
        &ctx.state,
        &ctx.bearer,
        reqwest::Method::GET,
        &super::super::dispatch::service_status_path(name),
        None,
    )
    .await
    {
        Ok(ForwardOutcome::Ok(svc)) => {
            let mut out = json!({ "name": name });
            for key in [
                "id",
                "status",
                "auth_mode",
                "credentials_status",
                "connection_id",
            ] {
                if let Some(v) = svc.get(key).filter(|v| !v.is_null()) {
                    out[key] = v.clone();
                }
            }
            Some(out)
        }
        other => {
            tracing::warn!(name, "re-read created service failed: {other:?}");
            Some(json!({ "name": name }))
        }
    }
}

/// A string field beside a request's id, from wherever the original result
/// mentions that request.
fn request_field<'a>(value: &'a Value, request_id: &str, field: &str) -> Option<&'a str> {
    match value {
        Value::Object(map) => {
            if map.get("request_id").and_then(Value::as_str) == Some(request_id)
                && let Some(v) = map.get(field).and_then(Value::as_str)
            {
                return Some(v);
            }
            map.values()
                .find_map(|v| request_field(v, request_id, field))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|v| request_field(v, request_id, field)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next_of(n: &Value) -> &str {
        n["url_elicitation"]["next"].as_str().unwrap()
    }

    #[test]
    fn a_note_is_added_without_disturbing_the_body() {
        let body = json!({ "error": "needs_authentication", "auth_url": "https://x" });
        let n = noted(
            &body,
            &Stopped::Declined(Some("access_denied".into())),
            Then::Replay,
        );
        assert_eq!(n["url_elicitation"]["status"], "declined");
        assert_eq!(n["url_elicitation"]["reason"], "access_denied");
        assert!(next_of(&n).contains("refused"));
        assert_eq!(n["auth_url"], "https://x");
        let timed_out = noted(&body, &Stopped::TimedOut, Then::Replay);
        assert!(timed_out["url_elicitation"].get("reason").is_none());
        assert!(next_of(&timed_out).contains("service_status"));
        let wrapped = noted(&json!([1]), &Stopped::Failed(None), Then::Report);
        assert_eq!(wrapped["result"], json!([1]));
        assert_eq!(wrapped["url_elicitation"]["status"], "failed");
    }

    /// Dismissing an approval link decides nothing, and an approval has no
    /// service connection to check: its notes say so, not the setup ones.
    #[test]
    fn an_approval_note_speaks_about_the_approval() {
        let body = json!({ "status": "pending_approval", "approval_id": "a1" });
        for stopped in [Stopped::Declined(None), Stopped::Cancelled] {
            let n = noted(&body, &stopped, Then::CallApproval);
            assert!(next_of(&n).contains("still pending, not denied"), "{n}");
            assert!(!next_of(&n).contains("refused"), "{n}");
        }
        let n = noted(&body, &Stopped::TimedOut, Then::CallApproval);
        assert!(next_of(&n).contains("approval_id"), "{n}");
        assert!(!next_of(&n).contains("service_status"), "{n}");
        let n = noted(&body, &Stopped::Failed(None), Then::CallApproval);
        assert!(!next_of(&n).contains("service_status"), "{n}");
    }

    /// The vault name and a template slot's key are different things: one is
    /// never reported as the other.
    #[test]
    fn request_fields_are_read_beside_their_request_id() {
        let body = json!({ "result": { "body": { "setup": { "requests": [
            { "request_id": "r1", "credential_key": "api_key", "setup_url": "u1" },
            { "request_id": "r2", "secret_name": "acme_token", "setup_url": "u2" },
        ] } } } });
        assert_eq!(request_field(&body, "r1", "secret_name"), None);
        assert_eq!(
            request_field(&body, "r1", "credential_key"),
            Some("api_key")
        );
        assert_eq!(
            request_field(&body, "r2", "secret_name"),
            Some("acme_token")
        );
        assert_eq!(request_field(&body, "r3", "secret_name"), None);
    }
}
