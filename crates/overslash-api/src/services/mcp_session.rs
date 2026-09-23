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
    /// Nobody answered. The dialog was cancelled or dismissed, the client
    /// replied with a JSON-RPC error, the originator's poll timed out, the
    /// session disconnected, or the sweeper retired the row. The approval is
    /// untouched and still `pending`, so the caller re-emits the ordinary
    /// `pending_approval` envelope and the agent keeps the URL-reject
    /// fallback it would have had with elicitation switched off.
    Abandoned,
}

const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long the originator polls its row before giving up and cancelling it.
///
/// `pub(crate)` because it is also the ceiling the background sweeper derives
/// its reap window from ([`crate::config::Config::mcp_elicitation_reap_after_secs`]):
/// no row older than this can still have anybody listening, and no reap window
/// shorter than this is safe.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// The platform default for a binding that has never expressed a choice.
///
/// Storage records only the explicit opt-out
/// (`mcp_client_agent_bindings.elicitation_opted_out`), so this is the other
/// half of the answer and the one place to change if the default ever flips
/// back. It is not AND-ed with the client's declared capability here on
/// purpose: capabilities are unknown when a binding is created, and the
/// capability check belongs at request time in `elicitation_eligible`.
pub(crate) const ELICITATION_DEFAULT_ENABLED: bool = true;

/// How long an unanswered elicitation suppresses further elicitation for the
/// same agent.
///
/// A `cancelled` row is the only signal the protocol gives us that the peer
/// could not, or would not, answer: a headless client auto-cancels in
/// milliseconds, and a human who just dismissed a dialog does not want the
/// model's immediate retry to raise another one. Keyed on the agent rather
/// than the approval because every gated call mints a *fresh* approval row —
/// a per-approval counter would never bind.
///
/// Long enough to swallow a model's retry burst, short enough that a human
/// who dismissed one dialog and then asks again gets a fresh one. Comfortably
/// inside `mcp_elicitation_retention_secs` (>= 720s), so the rows it reads are
/// never purged out from under it.
pub(crate) const CANCEL_COOLDOWN: Duration = Duration::from_secs(120);

/// Insert a fresh `pending_mcp_elicitations` row. Called by the originator
/// pod just before it emits `elicitation/create` on its SSE stream.
pub async fn open(
    state: &AppState,
    ext: &axum::http::Extensions,
    elicit_id: &str,
    session_id: Uuid,
    agent_identity_id: Uuid,
    approval_id: Uuid,
) -> Result<(), sqlx::Error> {
    repo::insert(
        state.db(ext),
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
pub async fn await_completion(
    state: &AppState,
    ext: &axum::http::Extensions,
    elicit_id: &str,
) -> ElicitOutcome {
    await_completion_with_timeout(state, ext, elicit_id, DEFAULT_TIMEOUT).await
}

pub async fn await_completion_with_timeout(
    state: &AppState,
    ext: &axum::http::Extensions,
    elicit_id: &str,
    timeout: Duration,
) -> ElicitOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match repo::get(state.db(ext), elicit_id).await {
            Ok(Some(row)) => match row.status.as_str() {
                repo::STATUS_COMPLETED => {
                    return ElicitOutcome::Completed(row.final_response.unwrap_or(json!({})));
                }
                repo::STATUS_FAILED => {
                    return ElicitOutcome::Failed(row.final_response.unwrap_or(json!({})));
                }
                repo::STATUS_CANCELLED => return ElicitOutcome::Abandoned,
                // pending or claimed → keep polling
                _ => {}
            },
            Ok(None) => {
                // Row vanished (manual cleanup or cascade). Nobody is going
                // to answer it now.
                return ElicitOutcome::Abandoned;
            }
            Err(e) => {
                tracing::error!(elicit_id, "poll mcp elicitation failed: {e}");
                // Don't loop tight on a DB error — back off the same tick.
            }
        }

        if tokio::time::Instant::now() >= deadline {
            let _ = repo::cancel(state.db(ext), elicit_id).await;
            return ElicitOutcome::Abandoned;
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
    ext: &axum::http::Extensions,
    elicit_id: &str,
    elicit_response: &Value,
) -> anyhow::Result<()> {
    // Atomically claim. If we don't claim, another replica is handling it.
    let row = match repo::claim(state.db(ext), elicit_id).await? {
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

    // MCP separates the two negative outcomes, and so do we.
    //
    // `decline` is a human saying no — resolved as `deny` below, so a retry
    // does not re-prompt for something already refused.
    //
    // `cancel` is *no answer*. The dialog was dismissed, or the client never
    // rendered one: headless / `--print` Claude Code auto-cancels within
    // milliseconds because it has no UI (measured at 6ms against 2.1.278),
    // and a `tools/call`-only bridge that declared `elicitation` never shows
    // a dialog at all. Reading that as a denial silently kills an approval
    // the human never saw, and takes the URL-reject fallback away with it.
    // Retire the row instead and leave the approval `pending`: the
    // originator's SSE tail then answers the original `tools/call` with the
    // same `pending_approval` envelope the no-elicitation path returns.
    //
    // Anything that is neither `accept` nor `decline` lands here too,
    // including the `{action:"cancel"}` that `post_mcp` synthesises when the
    // client answers with a JSON-RPC error — which is exactly the "declared
    // elicitation but can't actually do it" case, where falling back is the
    // only correct answer.
    //
    // This runs after `claim` so only one replica retires the row, and uses
    // `cancel` rather than `fail` because `cancel` stamps `completed_at`,
    // which the post-cancel cooldown in `elicitation_eligible` reads.
    if action != "accept" && action != "decline" {
        repo::cancel(state.db(ext), elicit_id).await?;
        return Ok(());
    }

    // `decision` is *our* per-form choice the user picked when they accepted
    // the dialog. A `decline` carries no form content, so it is a flat deny.
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
            if let Some(ttl) = content.get("ttl").and_then(Value::as_str)
                && ttl != "forever"
            {
                body["ttl"] = json!(ttl);
            }
            body
        }
        other => {
            let err = json!({ "error": format!("unknown decision: {other}") });
            repo::fail(state.db(ext), elicit_id, &err).await?;
            return Ok(());
        }
    };

    // Mint a fresh user-session JWT for the resolver and an MCP bearer for
    // the agent's replay call. Both are minted from the binding looked up
    // by `agent_identity_id`.
    let binding = overslash_db::repos::mcp_client_agent_binding::get_by_agent_identity(
        state.db(ext),
        row.agent_identity_id,
    )
    .await?;
    let Some(binding) = binding else {
        let err = json!({ "error": "mcp binding gone" });
        repo::fail(state.db(ext), elicit_id, &err).await?;
        return Ok(());
    };

    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());

    // ── User session JWT (resolver).
    // `binding.user_identity_id` is an identity_id, not a `users.id` —
    // resolve the FK before looking up the user row. Email comes off the
    // identity directly so we don't need a users.id at all for that.
    let user_identity = overslash_db::repos::identity::get_by_id(
        state.db(ext),
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
        .header(
            "Cookie",
            format!(
                "{}={user_session_jwt}",
                crate::cookies::name_for(state, crate::cookies::SESSION)
            ),
        )
        .json(&resolve_body)
        .send()
        .await?;

    if !resolve_resp.status().is_success() {
        let status = resolve_resp.status();
        let body = resolve_resp.text().await.unwrap_or_default();
        let err = json!({ "error": format!("resolve {status}: {body}") });
        repo::fail(state.db(ext), elicit_id, &err).await?;
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
        repo::fail(state.db(ext), elicit_id, &final_resp).await?;
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
        let updated = repo::complete(state.db(ext), elicit_id, &call_body).await?;
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
        repo::fail(state.db(ext), elicit_id, &err).await?;
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
