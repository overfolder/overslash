//! Starting a hybrid call: run it off the connection, then wait on it.
//!
//! The framing matters, because the obvious one does not work. A hybrid call is
//! **not** a synchronous call that gets promoted — an in-flight upstream request
//! cannot be handed to a leased row without either sending it twice or
//! degrading to a detached task with no durable record.
//!
//! So the request path never dials. The spawned job owns an `executions` row
//! from *before* the first byte goes out and dials exactly once; this connection
//! is a spectator with a deadline. Beat the deadline and the caller gets the
//! ordinary `called` envelope, rendered by the same `render_stored` the
//! synchronous path uses. Miss it and the caller gets the same `accepted`
//! envelope `async_accept` produces, and polls. Nothing is handed over at the
//! deadline except who is doing the reporting.
//!
//! See DECISIONS D68.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::response::{IntoResponse, Response};
use tokio::sync::{Semaphore, oneshot};
use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::services::async_executor::job::{InlineOutcome, JobMode};
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::AuthContext,
};

use super::call::UpstreamErrored;
use super::dto::{CallRequest, CallResponse, ResolvedMeta};

/// Per-replica cap on concurrently running hybrid jobs.
///
/// The worker loop bounds itself with `worker_concurrency` because a claimed row
/// costs a lease and a database connection. Hybrid spawns from the request path,
/// where nothing else provides back-pressure, so without this a burst of
/// requests is a burst of detached tasks against the same background pool the
/// worker is sized for.
fn permits(state: &AppState) -> Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PERMITS
        .get_or_init(|| {
            Arc::new(Semaphore::new(
                state.config.async_execution.hybrid_max_inflight,
            ))
        })
        .clone()
}

/// Start a hybrid call and wait on it for `handoff`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn start(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    auth: &AuthContext,
    identity_id: Uuid,
    req: &CallRequest,
    meta: &ResolvedMeta,
    action_req: &overslash_core::types::ActionRequest,
    auth_header_present: bool,
    call_timeout: crate::services::call_timeout::CallTimeout,
    handoff: Duration,
    call_tags: &[String],
    ip: Option<&str>,
    upstream_tpl: &str,
    // Which rung of the wait-mode cascade produced `hybrid` — `None` when the
    // caller named it. Rides through the saturation fall-through too, so a
    // call answered on the async queue still reports where its mode came from
    // rather than looking caller-driven.
    mode_source: Option<&'static str>,
) -> Result<Response> {
    // Saturated: fall through to the ordinary async queue rather than queueing
    // on the semaphore. The caller gets the same `accepted` envelope it would
    // have got on a handoff, so degradation under load is invisible to it —
    // only slower, because a worker picks it up on its next tick instead of a
    // task starting immediately.
    let Ok(permit) = permits(state).try_acquire_owned() else {
        tracing::info!("hybrid in-flight cap reached; accepting onto the async queue instead");
        overslash_metrics::actions::record_hybrid_outcome(upstream_tpl, "queued_saturated");
        return super::async_accept::accept(
            state,
            ext,
            scope,
            auth,
            identity_id,
            req,
            meta,
            action_req,
            auth_header_present,
            call_timeout,
            call_tags,
            ip,
            upstream_tpl,
            mode_source,
        )
        .await;
    };

    // The same builder `async_accept` and the permission gate use, so "a hybrid
    // call runs the identical request an async one would have" is a fact about
    // the code rather than a claim about it.
    let payload =
        super::replay_payload::build(meta, req, action_req, auth_header_present, call_timeout)
            .ok_or_else(|| AppError::Internal("could not serialize hybrid call payload".into()))?;

    // Wide enough to cover the call plus the work after the upstream answers.
    // Unlike a queued row this is not a deadline to *start* by — the job is
    // already running — it is the point past which the wall-clock sweep gives
    // up on it.
    let expires_at = time::OffsetDateTime::now_utc()
        + time::Duration::milliseconds(
            (call_timeout.ms() + state.config.async_execution.lease_ttl_secs * 1_000) as i64,
        );

    let (service_key, instance_id) = if auth_header_present {
        (
            meta.service_scope.as_ref().map(|s| s.service_key.as_str()),
            meta.instance_id,
        )
    } else {
        (None, None)
    };

    // Inserted already-claimed, before anything is dialled. A database outage
    // therefore turns a hybrid call into a 500 where a synchronous one would
    // have succeeded — the correct direction to fail, since the alternative is
    // dialling an upstream with nowhere to put the answer.
    let claim = scope
        .create_hybrid_execution(
            overslash_db::repos::execution::AsyncExecutionInput {
                org_id: auth.org_id,
                identity_id,
                request: &payload,
                service_key,
                service_instance_id: instance_id,
                tags: call_tags,
                render_verbose: req.verbose,
                template_key: Some(upstream_tpl),
                description: meta.description.as_deref(),
                client_ip: ip,
                expires_at,
            },
            crate::services::async_executor::worker_id(),
            state.config.async_execution.lease_ttl_secs as i64,
        )
        .await?;

    let execution_id = claim.id;
    let (tx, rx) = oneshot::channel::<InlineOutcome>();

    // `for_spawn` is what keeps this off the request pool and out of the
    // shared-router test harness's resolver; see its doc comment.
    let job_state = state.for_spawn(ext);
    let job_db = job_state.db.clone();
    let shutdown = crate::services::shutdown::subscribe();
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = crate::services::async_executor::job::execute(
            job_state,
            job_db,
            claim,
            shutdown,
            JobMode::Hybrid { observer: Some(tx) },
        )
        .await
        {
            tracing::error!("hybrid execution {execution_id} failed unexpectedly: {e}");
        }
    });

    let started = std::time::Instant::now();
    // `biased` with the receiver first so an outcome that lands in the same tick
    // as the timer wins deterministically. Without it a fast call sitting exactly
    // on the boundary would answer 200 or 202 at random.
    let inline = tokio::select! {
        biased;
        received = rx => received.ok(),
        _ = tokio::time::sleep(handoff) => None,
    };

    match inline {
        Some(InlineOutcome::Executed {
            result,
            is_error,
            upstream_errored,
        }) => {
            overslash_metrics::actions::record_hybrid_outcome(upstream_tpl, "inline");
            let rendered =
                super::render_stored(state, ext, &result, req, meta, auth.org_id, identity_id)
                    .await;
            let mut resp = (
                axum::http::StatusCode::OK,
                axum::Json(CallResponse::Called {
                    result: rendered,
                    action_description: meta.description.clone(),
                    is_error,
                    execution_id: Some(execution_id),
                }),
            )
                .into_response();
            if upstream_errored {
                resp.extensions_mut().insert(UpstreamErrored);
            }
            Ok(resp)
        }
        // Failed before the handoff, so there is still a caller to tell. The
        // typed error reproduces the envelope the synchronous path would have
        // produced; without one, the row carries the detail and a plain 502 is
        // the honest summary.
        Some(InlineOutcome::Failed { message, error }) => {
            overslash_metrics::actions::record_hybrid_outcome(upstream_tpl, "inline_failed");
            Err(error.map_or_else(|| AppError::BadGateway(message), |e| *e))
        }
        // Either the timer won, or the job ended without an answer for us
        // (cancelled, lease lost, shutdown). Both mean the same thing to the
        // caller: it is off this connection now, poll the row.
        None => {
            overslash_metrics::actions::record_hybrid_outcome(upstream_tpl, "handed_off");
            overslash_metrics::actions::record_hybrid_handoff_seconds(started.elapsed());

            // Audited only on this branch, unlike `async_accept` which audits
            // every accept. A hybrid call that answered inline was never
            // "accepted" in the sense this row means, and tagging every fast
            // call accepted-then-executed would make the trail say something
            // that did not happen.
            let _ = scope
                .clone()
                .log_audit_tagged(
                    overslash_db::repos::audit::AuditEntry {
                        org_id: auth.org_id,
                        identity_id: Some(identity_id),
                        action: "action.accepted",
                        resource_type: req.service.as_deref(),
                        resource_id: Some(execution_id),
                        detail: serde_json::json!({
                            "execution_id": execution_id,
                            "service": req.service,
                            "action": req.action,
                            "timeout_ms": call_timeout.ms(),
                            "execution_mode": "hybrid",
                            "execution_mode_source": mode_source,
                            "handed_off_after_ms": handoff.as_millis() as u64,
                        }),
                        description: meta.description.as_deref(),
                        ip_address: ip,
                    },
                    call_tags,
                )
                .await;

            Ok((
                axum::http::StatusCode::ACCEPTED,
                axum::Json(CallResponse::Accepted {
                    execution_id,
                    execution_url: state
                        .config
                        .dashboard_url_for(&format!("/executions/{execution_id}")),
                    action_description: meta.description.clone(),
                    expires_at: crate::routes::util::fmt_time(expires_at),
                    timeout_ms: call_timeout.ms(),
                    poll_after_ms: crate::routes::approvals::POLL_AFTER_MS,
                    execution_mode_source: mode_source,
                }),
            )
                .into_response())
        }
    }
}
