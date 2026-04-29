//! Coordination state for the MCP elicitation flow.
//!
//! Backs the `pending_mcp_elicitations` table that lets multiple API replicas
//! cooperate on a single elicitation round-trip. The originator pod inserts a
//! row and polls; the receiver pod (which may be a different replica behind
//! the load balancer) drives resolve+call and writes the final action result
//! into the row. The originator emits whatever ends up in `final_response` on
//! its SSE stream.
//!
//! See `docs/design/mcp-elicitation-approvals.md` (Flow A).

use std::time::Duration;

use overslash_db::repos::mcp_elicitation as repo;
use serde_json::{Value, json};
use tokio::time::sleep;
use uuid::Uuid;

use crate::AppState;

/// Outcome surfaced to the originator's SSE stream.
#[derive(Debug)]
pub enum ElicitOutcome {
    /// Resolve+call ran successfully; emit `value` as the elicit response.
    Completed(Value),
    /// Resolve+call failed (either because the user denied, or because the
    /// loopback resolve/call returned an error envelope). Emit `value` as a
    /// JSON-RPC `result` payload that lets the model see what happened.
    Failed(Value),
    /// Row was cancelled (disconnect, expiry, or the receiver couldn't claim
    /// it). Emit a JSON-RPC error to the model so it can fall back to URL.
    Cancelled,
}

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Insert a fresh `pending_mcp_elicitations` row. Called by the originator
/// pod just before it emits `elicitation/create` on its SSE stream.
pub async fn open(
    state: &AppState,
    elicit_id: &str,
    session_id: Uuid,
    agent_identity_id: Uuid,
    approval_id: Uuid,
) -> Result<(), sqlx::Error> {
    repo::insert(
        &state.db,
        elicit_id,
        session_id,
        agent_identity_id,
        approval_id,
    )
    .await
}

/// Poll the row until it reaches a terminal status or the timeout fires.
///
/// On timeout we mark the row `cancelled` so a late-arriving receiver doesn't
/// drive resolve+call against a stream nobody's listening on. Caller should
/// emit a JSON-RPC error on its SSE stream.
pub async fn await_completion(state: &AppState, elicit_id: &str) -> ElicitOutcome {
    await_completion_with_timeout(state, elicit_id, DEFAULT_TIMEOUT).await
}

pub async fn await_completion_with_timeout(
    state: &AppState,
    elicit_id: &str,
    timeout: Duration,
) -> ElicitOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match repo::get(&state.db, elicit_id).await {
            Ok(Some(row)) => match row.status.as_str() {
                repo::STATUS_COMPLETED => {
                    return ElicitOutcome::Completed(row.final_response.unwrap_or(json!({})));
                }
                repo::STATUS_FAILED => {
                    return ElicitOutcome::Failed(row.final_response.unwrap_or(json!({})));
                }
                repo::STATUS_CANCELLED => return ElicitOutcome::Cancelled,
                // pending or claimed → keep polling
                _ => {}
            },
            Ok(None) => {
                // Row vanished (manual cleanup or cascade). Treat as cancelled.
                return ElicitOutcome::Cancelled;
            }
            Err(e) => {
                tracing::error!(elicit_id, "poll mcp elicitation failed: {e}");
                // Don't loop tight on a DB error — back off the same tick.
            }
        }

        if tokio::time::Instant::now() >= deadline {
            let _ = repo::cancel(&state.db, elicit_id).await;
            return ElicitOutcome::Cancelled;
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Drive the resolve + call HTTP loopback for a freshly-answered elicitation,
/// then write the final action result into the row. Idempotent: if the row
/// is already non-pending, returns Ok(()) silently.
///
/// `elicit_response` is the full client-supplied object:
///   { action: "accept"|"decline"|"cancel", content?: { decision, ttl, ... } }
pub async fn complete_from_elicitation(
    state: &AppState,
    elicit_id: &str,
    elicit_response: &Value,
) -> anyhow::Result<()> {
    // Atomically claim. If we don't claim, another replica is handling it.
    let row = match repo::claim(&state.db, elicit_id).await? {
        Some(r) => r,
        None => return Ok(()),
    };

    let action = elicit_response
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("cancel");
    let content = elicit_response
        .get("content")
        .cloned()
        .unwrap_or(Value::Null);

    // `action` is the MCP-spec-level outcome (accept / decline / cancel).
    // `decision` is *our* per-form choice the user picked when they did
    // accept the dialog. A decline at the MCP level means "the user said
    // no to this approval prompt" — that's a `deny` resolution as far as
    // the approval row is concerned, not just a row-level cancel. Without
    // this the approval stays `pending`, the elicitation re-fires on
    // retry, and the user gets prompted in a loop.
    let decision = if action == "accept" {
        content
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("deny")
    } else {
        "deny"
    };

    let resolve_body = match decision {
        "allow" => json!({ "resolution": "allow" }),
        "deny" => json!({ "resolution": "deny" }),
        "bubble_up" => json!({ "resolution": "bubble_up" }),
        "allow_remember" => {
            // Only forward `remember_keys` when the client actually picked a
            // non-empty subset. The resolve endpoint rejects an empty array
            // but treats a missing field as "remember every key on the
            // approval" — that's the right default for an MCP form that
            // doesn't expose per-key checkboxes.
            let mut body = json!({ "resolution": "allow_remember" });
            if let Some(keys) = content.get("remember_keys").and_then(Value::as_array) {
                let cleaned: Vec<&str> = keys.iter().filter_map(Value::as_str).collect();
                if !cleaned.is_empty() {
                    body["remember_keys"] = json!(cleaned);
                }
            }
            if let Some(ttl) = content.get("ttl").and_then(Value::as_str) {
                if ttl != "forever" {
                    body["ttl"] = json!(ttl);
                }
            }
            body
        }
        other => {
            let err = json!({ "error": format!("unknown decision: {other}") });
            repo::fail(&state.db, elicit_id, &err).await?;
            return Ok(());
        }
    };

    // Mint a fresh user-session JWT for the resolver and an MCP bearer for
    // the agent's replay call. Both are minted from the binding looked up
    // by `agent_identity_id`.
    let binding = overslash_db::repos::mcp_client_agent_binding::get_by_agent_identity(
        &state.db,
        row.agent_identity_id,
    )
    .await?;
    let Some(binding) = binding else {
        let err = json!({ "error": "mcp binding gone" });
        repo::fail(&state.db, elicit_id, &err).await?;
        return Ok(());
    };

    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());

    // ── User session JWT (resolver).
    // `binding.user_identity_id` is an identity_id, not a `users.id` —
    // resolve the FK before looking up the user row. Email comes off the
    // identity directly so we don't need a users.id at all for that.
    let user_identity = overslash_db::repos::identity::get_by_id(
        &state.db,
        binding.org_id,
        binding.user_identity_id,
    )
    .await
    .ok()
    .flatten();
    let user_email = user_identity
        .as_ref()
        .and_then(|i| i.email.clone())
        .unwrap_or_default();
    // Use the real users.id when available so the JWT's `user_id` claim
    // contract holds (sub = identity_id, user_id = users.id). Falls back
    // to None for legacy identities without a user row.
    let users_pk = user_identity.as_ref().and_then(|i| i.user_id);
    let user_session_jwt = mint_user_session(
        &signing_key,
        binding.user_identity_id,
        binding.org_id,
        user_email.clone(),
        users_pk,
    )?;

    // ── Agent MCP bearer for the replay call.
    let agent_mcp = crate::services::jwt::mint_mcp(
        &signing_key,
        row.agent_identity_id,
        binding.org_id,
        user_email,
        crate::services::oauth_as::ACCESS_TOKEN_TTL_SECS,
        Some(binding.client_id.clone()),
    )?;

    // ── Resolve. Send the user-session JWT as a cookie so the WriteAcl
    // path treats this as a dashboard-resolver call.
    let resolve_url = format!(
        "{}/v1/approvals/{}/resolve",
        state.config.public_url.trim_end_matches('/'),
        row.approval_id,
    );
    let resolve_resp = state
        .http_client
        .post(&resolve_url)
        .header("Cookie", format!("oss_session={}", user_session_jwt))
        .json(&resolve_body)
        .send()
        .await?;

    if !resolve_resp.status().is_success() {
        let status = resolve_resp.status();
        let body = resolve_resp.text().await.unwrap_or_default();
        let err = json!({ "error": format!("resolve {status}: {body}") });
        repo::fail(&state.db, elicit_id, &err).await?;
        return Ok(());
    }

    // ── Call (trigger replay) — only on allow / allow_remember. A deny or
    // bubble_up is a terminal "no" from the user; emit it as `Failed` so the
    // SSE stream surfaces `isError: true` to the model. Marking COMPLETED
    // would let a deny look like a successful tool call.
    if matches!(decision, "deny" | "bubble_up") {
        let final_resp = json!({
            "resolution": decision,
            "result": resolve_resp.json::<Value>().await.unwrap_or(Value::Null),
        });
        repo::fail(&state.db, elicit_id, &final_resp).await?;
        return Ok(());
    }

    let call_url = format!(
        "{}/v1/approvals/{}/call",
        state.config.public_url.trim_end_matches('/'),
        row.approval_id,
    );
    let call_resp = state
        .http_client
        .post(&call_url)
        .bearer_auth(&agent_mcp)
        .json(&json!({}))
        .send()
        .await?;

    let call_status = call_resp.status();
    let call_body: Value = call_resp.json().await.unwrap_or(Value::Null);

    if call_status.is_success() {
        let updated = repo::complete(&state.db, elicit_id, &call_body).await?;
        if updated == 0 {
            // Row was already terminal (cancelled by originator timeout or
            // by an admin disconnect) when our /call returned. The action
            // did execute against the upstream — surface that to ops since
            // the SSE consumer has already moved on with a cancelled frame.
            tracing::warn!(
                elicit_id,
                "elicitation row was cancelled before /call returned; \
                 upstream side-effect ran but client saw a cancelled frame",
            );
        }
    } else {
        let err = json!({ "error": format!("call {call_status}"), "body": call_body });
        repo::fail(&state.db, elicit_id, &err).await?;
    }
    Ok(())
}

fn mint_user_session(
    signing_key: &[u8],
    user_identity_id: Uuid,
    org_id: Uuid,
    email: String,
    user_pk: Option<Uuid>,
) -> anyhow::Result<String> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = crate::services::jwt::Claims {
        sub: user_identity_id,
        org: org_id,
        email,
        aud: crate::services::jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 600,
        // `user_id` claim is the human's `users.id` (per jwt.rs Claims doc),
        // distinct from `sub` (identities.id). Falls back to None when the
        // identity isn't backed by a users row.
        user_id: user_pk,
        mcp_client_id: None,
    };
    Ok(crate::services::jwt::mint(signing_key, &claims)?)
}
