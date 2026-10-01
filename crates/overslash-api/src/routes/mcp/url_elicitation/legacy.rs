//! The 2025-era transport for URL-mode elicitation: one SSE stream around the
//! whole plan, with the client's answers crossing replicas through
//! `mcp_url_elicitations`.

use super::*;

// ---------------------------------------------------------------------------
// 2025-era transport: an SSE stream around the whole plan
// ---------------------------------------------------------------------------

pub(in crate::routes::mcp) fn legacy_stream(ctx: Ctx, rpc_id: Value, plan: Plan) -> Reply {
    let (tx, rx) = tokio::sync::mpsc::channel::<Value>(8);
    tokio::spawn(async move {
        let reply = drive_legacy(&ctx, &plan, &tx).await;
        let frame = match reply {
            Reply::Result(result) => json!({ "jsonrpc": "2.0", "id": rpc_id, "result": result }),
            Reply::Error(code, message) => json!({
                "jsonrpc": "2.0", "id": rpc_id,
                "error": { "code": code, "message": message },
            }),
            Reply::Stream(_) | Reply::Deferred(_) => json!({
                "jsonrpc": "2.0", "id": rpc_id,
                "error": { "code": INTERNAL_ERROR, "message": "unexpected nested reply" },
            }),
        };
        let _ = tx.send(frame).await;
    });
    let events = stream::unfold(rx, |mut rx| async move {
        let frame = rx.recv().await?;
        Some((
            Ok::<_, Infallible>(Event::default().json_data(frame).unwrap_or_default()),
            rx,
        ))
    });
    Reply::Stream(
        Sse::new(events)
            .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
            .into_response(),
    )
}

async fn drive_legacy(ctx: &Ctx, plan: &Plan, tx: &tokio::sync::mpsc::Sender<Value>) -> Reply {
    let Some(agent) = ctx.auth.identity_id else {
        return stop(ctx, plan, Stopped::Failed(None)).await;
    };
    for handoff in &plan.handoffs {
        let eid = format!("{URL_ID_PREFIX}{}", Uuid::new_v4());
        if let Err(e) =
            overslash_db::repos::mcp_url_elicitation::insert(ctx.state.db(&ctx.ext), &eid, agent)
                .await
        {
            tracing::error!("open url elicitation failed: {e}");
            return stop(ctx, plan, Stopped::Failed(None)).await;
        }
        let ask = json!({
            "jsonrpc": "2.0",
            "id": eid,
            "method": "elicitation/create",
            "params": url_params(handoff, Some(&eid)),
        });
        if tx.send(ask).await.is_err() {
            // The client hung up; nobody is left to answer.
            return stop(ctx, plan, Stopped::Cancelled).await;
        }

        let waited = wait_for(ctx, &handoff.watch, || async {
            if tx.is_closed() {
                return Some(Stopped::Cancelled);
            }
            match overslash_db::repos::mcp_url_elicitation::get(ctx.state.db(&ctx.ext), &eid).await
            {
                Ok(Some(row)) => match row.action.as_deref() {
                    Some("accept") | None => None,
                    Some(other) => Some(Stopped::from_action(other)),
                },
                _ => None,
            }
        })
        .await;
        // The out-of-band interaction is over whenever the wait did not end
        // on the client's own answer — success, refusal, failure or timeout
        // alike — and the notification is what lets a client drop its
        // "waiting for the browser" state. The final result follows.
        if waited.as_ref().err().is_none_or(Stopped::ended_in_browser) {
            let _ = tx
                .send(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/elicitation/complete",
                    "params": { "elicitationId": eid },
                }))
                .await;
        }
        if let Err(stopped) = waited {
            return stop(ctx, plan, stopped).await;
        }
    }
    finish(ctx, plan).await
}

/// A 2025-era client's answer to a URL elicitation, delivered as a bare
/// JSON-RPC response on `POST /mcp`. Recorded for the replica holding the
/// stream; only the agent the elicitation belongs to may answer it.
pub(in crate::routes::mcp) async fn record_legacy_answer(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    elicit_id: &str,
    response: &Value,
) -> Response {
    let owner_ok = matches!(
        overslash_db::repos::mcp_url_elicitation::get(state.db(ext), elicit_id).await,
        Ok(Some(row)) if Some(row.agent_identity_id) == auth.identity_id
    );
    if !owner_ok {
        return rpc_error_response(
            Value::String(elicit_id.to_string()),
            INVALID_REQUEST,
            "elicitation not found or not addressable by this caller",
        );
    }
    // A JSON-RPC error answer is the client saying it could not do it.
    let action = response
        .get("result")
        .and_then(|r| r.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("cancel");
    if let Err(e) =
        overslash_db::repos::mcp_url_elicitation::answer(state.db(ext), elicit_id, action).await
    {
        tracing::error!(elicit_id, "record url elicitation answer failed: {e}");
    }
    (StatusCode::ACCEPTED, "").into_response()
}
