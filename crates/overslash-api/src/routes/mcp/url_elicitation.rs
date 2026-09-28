//! URL-mode elicitation: hand the user a browser link through the MCP
//! client, wait for the browser flow to finish, then answer the tool call as
//! if the link had never been needed.
//!
//! Every recovery envelope Overslash returns ends with a human opening a URL:
//! a provider OAuth link (`needs_authentication`, `reauth_required`,
//! `missing_scopes`), a credential-entry page (`request_secret`, the
//! `create_service` setup bundle), a connect link (`create_service` for an
//! OAuth template), or the approval page when the user has turned "Approve in
//! your client" off. Without URL mode the agent relays the link and the user
//! comes back to say "done". With it, the client offers to open the link, and
//! the original call finishes on its own:
//!
//! - an auth envelope **replays** the call once the flow completes;
//! - a setup / secret link **reports** the original result, marked completed;
//! - an approval link **calls** the approved action.
//!
//! When the link is declined, dismissed, fails or times out, the agent gets
//! the original envelope with a `url_elicitation` note saying which, so it
//! knows the user already saw the prompt. A URL elicitation never denies or
//! resolves anything by itself.
//!
//! On by default wherever the client declares `elicitation.url` — it is not
//! governed by the "Approve in your client" toggle, which is about answering
//! approvals *inside* the client; URL mode sends the user out of it.
//!
//! Two transports, one plan:
//! - **2025-era (SSE).** The tool call's response is an SSE stream carrying one
//!   `elicitation/create { mode: "url", elicitationId }` per link, a
//!   `notifications/elicitation/complete` when each finishes, then the result.
//!   The client's accept/decline arrives on another POST, possibly on another
//!   replica, and crosses over through `mcp_url_elicitations`.
//! - **2026-07-28 (MRTR).** The call answers `input_required` with the link;
//!   the client opens it and retries. The retry waits for the flow (an SSE
//!   response with keep-alives, so the connection survives the wait) and
//!   answers with the next link or the result. The plan rides in the signed
//!   `requestState`.

use serde::Serialize;

use super::dispatch::{dispatch_call, dispatch_read};
use super::modern::{STEP_URL, mint_url_state};
use super::tools_call::{Reply, text_result};
use super::*;

/// How long one browser hand-off may take before the call gives up on it —
/// the same ceiling the form dialogs and the sweeper already work to.
pub(super) const URL_TIMEOUT: Duration = mcp_session::DEFAULT_TIMEOUT;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// JSON-RPC ids of legacy URL elicitations. Still `elicit_`-prefixed, so
/// `post_mcp` recognises the client's answer as an elicitation answer.
pub(super) const URL_ID_PREFIX: &str = "elicit_url_";

/// The field added to a fallback body saying how the hand-off ended.
const NOTE_FIELD: &str = "url_elicitation";

/// A browser hand-off Overslash can watch to completion.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Watch {
    /// An `oauth_connection_flows` row: done when the callback stamps it.
    OauthFlow { id: String },
    /// A `secret_requests` row: done when it is fulfilled.
    SecretRequest { id: String },
    /// An approval: done when it is no longer pending.
    Approval { id: Uuid },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(super) struct Handoff {
    pub(super) url: String,
    pub(super) message: String,
    pub(super) watch: Watch,
}

/// What finishing every hand-off earns the caller.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Then {
    /// Run the original call again: the credential it lacked now exists.
    Replay,
    /// Return the original result, marked completed: it *was* the setup.
    Report,
    /// Trigger the approved action (the plan's `Approval` hand-off).
    CallApproval,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(super) struct Plan {
    pub(super) handoffs: Vec<Handoff>,
    pub(super) then: Then,
    /// The body the call produced, which the agent gets back (with a note)
    /// if the hand-offs do not complete.
    pub(super) fallback: Value,
    /// Whether that body is a typed error envelope (`isError: true`).
    pub(super) fallback_is_error: bool,
    /// The `pending_mcp_elicitations` row that holds an approval's auto-call
    /// off while its link is out. `None` for every other plan.
    #[serde(default)]
    pub(super) approval_row: Option<String>,
}

/// How a plan ended without completing, as the note reports it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Stopped {
    Declined,
    Cancelled,
    TimedOut,
    Failed,
}

impl Stopped {
    fn note(self) -> &'static str {
        match self {
            Stopped::Declined => "declined",
            Stopped::Cancelled => "cancelled",
            Stopped::TimedOut => "timed_out",
            Stopped::Failed => "failed",
        }
    }

    pub(super) fn from_action(action: &str) -> Self {
        match action {
            "decline" => Stopped::Declined,
            _ => Stopped::Cancelled,
        }
    }
}

/// Everything a waiting hand-off needs, owned, so it can outlive the handler
/// on a spawned stream.
#[derive(Clone)]
pub(super) struct Ctx {
    pub(super) state: AppState,
    pub(super) ext: axum::http::Extensions,
    pub(super) auth: AuthContext,
    pub(super) bearer: String,
    pub(super) tool_name: String,
    pub(super) args: Value,
}

// ---------------------------------------------------------------------------
// Eligibility and planning
// ---------------------------------------------------------------------------

/// Did the client declare URL-mode elicitation? `declared` as in
/// [`super::elicitation::elicitation_eligible`]: the request's own `_meta`
/// capabilities on 2026-07-28, `None` to read what `initialize` stored.
pub(super) async fn url_eligible(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    declared: Option<&Value>,
) -> bool {
    if auth.identity_id.is_none() {
        return false;
    }
    match declared {
        Some(caps) => supports_url_elicitation(caps),
        None => {
            let Some(client_id) = auth.mcp_client_id.as_deref() else {
                return false;
            };
            matches!(
                overslash_db::repos::oauth_mcp_client::get_by_client_id(state.db(ext), client_id)
                    .await,
                Ok(Some(c)) if c.capabilities.as_ref().is_some_and(supports_url_elicitation)
            )
        }
    }
}

pub(super) fn supports_url_elicitation(capabilities: &Value) -> bool {
    capabilities
        .get("elicitation")
        .and_then(|e| e.get("url"))
        .is_some_and(Value::is_object)
}

/// The hand-offs a forwarded outcome asks of the user, if any.
///
/// Typed auth envelopes are planned from any tool. Setup and connect links
/// only from Overslash's own platform actions (`service: "overslash"`), so an
/// upstream API that happens to return `flow_id` + `auth_url` is never
/// mistaken for one.
pub(super) fn plan_for(
    state: &AppState,
    tool_name: &str,
    args: &Value,
    outcome: &ForwardOutcome,
) -> Option<Plan> {
    match outcome {
        ForwardOutcome::TypedError(envelope) => {
            let handoff = auth_handoff(state, envelope)?;
            Some(Plan {
                handoffs: vec![handoff],
                then: Then::Replay,
                fallback: envelope.clone(),
                fallback_is_error: true,
                approval_row: None,
            })
        }
        ForwardOutcome::Ok(value) => {
            let is_platform = tool_name == "overslash_call"
                && args.get("service").and_then(Value::as_str) == Some("overslash");
            if !is_platform {
                return None;
            }
            let mut handoffs = Vec::new();
            collect_setup_handoffs(state, value, &mut handoffs);
            if handoffs.is_empty() {
                return None;
            }
            Some(Plan {
                handoffs,
                then: Then::Report,
                fallback: value.clone(),
                fallback_is_error: false,
                approval_row: None,
            })
        }
    }
}

/// An approval the user reviews on the dashboard instead of in a dialog.
pub(super) fn plan_for_approval(pending_outcome: &Value) -> Option<Plan> {
    let id = pending_outcome
        .get("approval_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())?;
    let url = pending_outcome
        .get("approval_url")
        .and_then(Value::as_str)?;
    let summary = pending_outcome
        .get("action_description")
        .and_then(Value::as_str)
        .unwrap_or("an action");
    Some(Plan {
        handoffs: vec![Handoff {
            url: url.to_string(),
            message: format!("Review and approve in Overslash: {summary}"),
            watch: Watch::Approval { id },
        }],
        then: Then::CallApproval,
        fallback: pending_outcome.clone(),
        fallback_is_error: false,
        approval_row: None,
    })
}

fn auth_handoff(state: &AppState, envelope: &Value) -> Option<Handoff> {
    let code = envelope.get("error").and_then(Value::as_str)?;
    let url = envelope.get("auth_url").and_then(Value::as_str)?;
    let flow_id = own_flow_id(&state.config.public_url, url)?;
    let who = envelope
        .get("provider")
        .or_else(|| envelope.get("service"))
        .and_then(Value::as_str)
        .unwrap_or("the service");
    let message = match code {
        "needs_authentication" => format!("Connect your {who} account so the agent can continue."),
        "reauth_required" => {
            format!(
                "Your {who} connection needs to be re-authorized before the agent can continue."
            )
        }
        "missing_scopes" => {
            format!("Grant {who} the extra permissions this action needs.")
        }
        _ => return None,
    };
    Some(Handoff {
        url: url.to_string(),
        message,
        watch: Watch::OauthFlow { id: flow_id },
    })
}

/// The flow id of one of Overslash's own gated connect links
/// (`{public_url}/connect-authorize?id=…`). Anything else is not a link this
/// server can watch.
fn own_flow_id(public_url: &str, url: &str) -> Option<String> {
    let base = url::Url::parse(public_url.trim_end_matches('/')).ok()?;
    let link = url::Url::parse(url).ok()?;
    if link.origin() != base.origin() || link.path() != "/connect-authorize" {
        return None;
    }
    link.query_pairs()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .filter(|id| !id.is_empty())
}

/// Walk a platform result for the links it hands the user: a connect bundle
/// (`flow_id` + `auth_url`), and credential links (`request_id` +
/// `provide_url` / `setup_url`). The setup bundle's scalar `setup_url` has no
/// `request_id` and is skipped — its `requests[]` entries carry every link,
/// the first one included.
fn collect_setup_handoffs(state: &AppState, value: &Value, out: &mut Vec<Handoff>) {
    match value {
        Value::Object(map) => {
            let str_field = |k: &str| map.get(k).and_then(Value::as_str);
            if let (Some(_), Some(url)) = (str_field("flow_id"), str_field("auth_url"))
                && let Some(id) = own_flow_id(&state.config.public_url, url)
            {
                push_unique(
                    out,
                    Handoff {
                        url: url.to_string(),
                        message: "Connect the account for this service so the agent can use it."
                            .into(),
                        watch: Watch::OauthFlow { id },
                    },
                );
            }
            if let Some(request_id) = str_field("request_id")
                && let Some(url) = str_field("provide_url").or_else(|| str_field("setup_url"))
            {
                let what = str_field("secret_name")
                    .or_else(|| str_field("credential_key"))
                    .unwrap_or("the credential");
                push_unique(
                    out,
                    Handoff {
                        url: url.to_string(),
                        message: format!(
                            "Enter {what} in Overslash. It goes straight to the vault — the agent never sees it."
                        ),
                        watch: Watch::SecretRequest {
                            id: request_id.to_string(),
                        },
                    },
                );
            }
            for v in map.values() {
                collect_setup_handoffs(state, v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_setup_handoffs(state, v, out);
            }
        }
        _ => {}
    }
}

fn push_unique(out: &mut Vec<Handoff>, handoff: Handoff) {
    if !out.iter().any(|h| h.watch == handoff.watch) {
        out.push(handoff);
    }
}

/// Hold the approval's auto-call off while its link is out, exactly as a form
/// dialog does: the waiting call triggers the action itself once approved,
/// and an auto-call would race it. Returns the row id, or `None` if the row
/// could not be opened (the plan then falls back to the envelope).
pub(super) async fn open_approval_row(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    plan: &Plan,
) -> Option<String> {
    let Watch::Approval { id } = plan.handoffs.first()?.watch else {
        return None;
    };
    let agent = auth.identity_id?;
    let row_id = format!("{URL_ID_PREFIX}{}", Uuid::new_v4());
    match mcp_session::open(state, ext, &row_id, Uuid::new_v4(), agent, id).await {
        Ok(()) => Some(row_id),
        Err(e) => {
            tracing::error!("open url elicitation approval row failed: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Waiting
// ---------------------------------------------------------------------------

enum Progress {
    Pending,
    Done,
    Failed,
}

async fn progress(ctx: &Ctx, watch: &Watch) -> Progress {
    let db = ctx.state.db(&ctx.ext);
    let now = time::OffsetDateTime::now_utc();
    match watch {
        Watch::OauthFlow { id } => {
            match overslash_db::repos::oauth_connection_flow::completion(db, id).await {
                Ok(Some(f)) if f.org_id == ctx.auth.org_id => {
                    if f.completed_at.is_some() {
                        Progress::Done
                    } else if f.failed_at.is_some() || f.expires_at < now {
                        Progress::Failed
                    } else {
                        Progress::Pending
                    }
                }
                Ok(_) => Progress::Failed,
                Err(e) => {
                    tracing::warn!("poll oauth flow failed: {e}");
                    Progress::Pending
                }
            }
        }
        Watch::SecretRequest { id } => {
            match overslash_db::repos::secret_request::get(db, id).await {
                Ok(Some(r)) if r.org_id == ctx.auth.org_id => {
                    if r.fulfilled_at.is_some() {
                        Progress::Done
                    } else if r.expires_at < now {
                        Progress::Failed
                    } else {
                        Progress::Pending
                    }
                }
                Ok(_) => Progress::Failed,
                Err(e) => {
                    tracing::warn!("poll secret request failed: {e}");
                    Progress::Pending
                }
            }
        }
        Watch::Approval { id } => {
            let scope = overslash_db::OrgScope::new(ctx.auth.org_id, ctx.state.db_pool(&ctx.ext));
            match scope.get_approval(*id).await {
                Ok(Some(a)) if a.status == "pending" => Progress::Pending,
                Ok(Some(_)) => Progress::Done,
                Ok(None) => Progress::Failed,
                Err(e) => {
                    tracing::warn!("poll approval failed: {e}");
                    Progress::Pending
                }
            }
        }
    }
}

/// Wait for one hand-off. `answered` is consulted each tick so a legacy
/// client's decline can end the wait early; the modern retry passes a closure
/// that never answers, since its accept already arrived.
pub(super) async fn wait_for<F, Fut>(
    ctx: &Ctx,
    watch: &Watch,
    mut answered: F,
) -> Result<(), Stopped>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<Stopped>>,
{
    let deadline = tokio::time::Instant::now() + URL_TIMEOUT;
    loop {
        match progress(ctx, watch).await {
            Progress::Done => return Ok(()),
            Progress::Failed => return Err(Stopped::Failed),
            Progress::Pending => {}
        }
        if let Some(stopped) = answered().await {
            return Err(stopped);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Stopped::TimedOut);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------
// Finishing
// ---------------------------------------------------------------------------

/// Every hand-off completed: earn the plan's result.
pub(super) async fn finish(ctx: &Ctx, plan: &Plan) -> Reply {
    let reply = match plan.then {
        Then::Replay => {
            let outcome = match ctx.tool_name.as_str() {
                "overslash_read" => dispatch_read(&ctx.state, &ctx.bearer, &ctx.args).await,
                _ => dispatch_call(&ctx.state, &ctx.bearer, &ctx.args).await,
            };
            render(outcome)
        }
        Then::Report => Reply::Result(text_result(&with_note(&plan.fallback, "completed"))),
        Then::CallApproval => call_approval(ctx, plan).await,
    };
    retire_approval_row(ctx, plan, true).await;
    reply
}

/// A hand-off did not complete: the original body, with a note saying why.
pub(super) async fn stop(ctx: &Ctx, plan: &Plan, stopped: Stopped) -> Reply {
    retire_approval_row(ctx, plan, false).await;
    fallback(plan, stopped)
}

pub(super) fn fallback(plan: &Plan, stopped: Stopped) -> Reply {
    let body = with_note(&plan.fallback, stopped.note());
    if plan.fallback_is_error {
        Reply::Result(tool_error_result(&body))
    } else {
        Reply::Result(text_result(&body))
    }
}

async fn call_approval(ctx: &Ctx, plan: &Plan) -> Reply {
    let Some(Watch::Approval { id }) = plan.handoffs.first().map(|h| &h.watch) else {
        return fallback(plan, Stopped::Failed);
    };
    let scope = overslash_db::OrgScope::new(ctx.auth.org_id, ctx.state.db_pool(&ctx.ext));
    let status = match scope.get_approval(*id).await {
        Ok(Some(a)) => a.status,
        _ => return fallback(plan, Stopped::Failed),
    };
    if status != "allowed" {
        // Denied, bubbled up or expired on the dashboard: a real answer, so
        // the call fails the way a declined form dialog makes it fail.
        return Reply::Result(tool_error_result(&json!({
            "resolution": status,
            "approval_id": id,
        })));
    }
    let path = format!("/v1/approvals/{id}/call");
    render(forward(&ctx.state, &ctx.bearer, reqwest::Method::POST, &path, None).await)
}

fn render(outcome: Result<ForwardOutcome, String>) -> Reply {
    match outcome {
        Ok(ForwardOutcome::Ok(v)) => Reply::Result(text_result(&v)),
        Ok(ForwardOutcome::TypedError(e)) => Reply::Result(tool_error_result(&e)),
        Err(msg) => Reply::Error(INTERNAL_ERROR, msg),
    }
}

/// Release the approval's auto-call hold. `completed` when the waiting call
/// took the action over; otherwise `withdrawn`, which — unlike `cancelled` —
/// starts no form-dialog cooldown: a link nobody opened says nothing about
/// whether the client can render a dialog.
async fn retire_approval_row(ctx: &Ctx, plan: &Plan, completed: bool) {
    let Some(row) = plan.approval_row.as_deref() else {
        return;
    };
    let db = ctx.state.db(&ctx.ext);
    let r = if completed {
        overslash_db::repos::mcp_elicitation::complete(db, row, &json!({}))
            .await
            .map(|_| ())
    } else {
        overslash_db::repos::mcp_elicitation::withdraw(db, row).await
    };
    if let Err(e) = r {
        tracing::warn!(row, "retire url elicitation approval row failed: {e}");
    }
}

fn with_note(body: &Value, note: &str) -> Value {
    match body {
        Value::Object(map) => {
            let mut map = map.clone();
            map.insert(NOTE_FIELD.into(), json!(note));
            Value::Object(map)
        }
        other => json!({ "result": other, NOTE_FIELD: note }),
    }
}

/// The `elicitation/create` params for one hand-off. The legacy era adds its
/// `elicitationId`; 2026-07-28 removed it.
pub(super) fn url_params(handoff: &Handoff, elicitation_id: Option<&str>) -> Value {
    let mut params = json!({
        "mode": "url",
        "message": handoff.message,
        "url": handoff.url,
    });
    if let Some(id) = elicitation_id {
        params["elicitationId"] = json!(id);
    }
    params
}

// ---------------------------------------------------------------------------
// 2025-era transport: an SSE stream around the whole plan
// ---------------------------------------------------------------------------

pub(super) fn legacy_stream(ctx: Ctx, rpc_id: Value, plan: Plan) -> Reply {
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
        return stop(ctx, plan, Stopped::Failed).await;
    };
    for handoff in &plan.handoffs {
        let eid = format!("{URL_ID_PREFIX}{}", Uuid::new_v4());
        if let Err(e) =
            overslash_db::repos::mcp_url_elicitation::insert(ctx.state.db(&ctx.ext), &eid, agent)
                .await
        {
            tracing::error!("open url elicitation failed: {e}");
            return stop(ctx, plan, Stopped::Failed).await;
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
        if let Err(stopped) = waited {
            return stop(ctx, plan, stopped).await;
        }
        let _ = tx
            .send(json!({
                "jsonrpc": "2.0",
                "method": "notifications/elicitation/complete",
                "params": { "elicitationId": eid },
            }))
            .await;
    }
    finish(ctx, plan).await
}

/// A 2025-era client's answer to a URL elicitation, delivered as a bare
/// JSON-RPC response on `POST /mcp`. Recorded for the replica holding the
/// stream; only the agent the elicitation belongs to may answer it.
pub(super) async fn record_legacy_answer(
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

// ---------------------------------------------------------------------------
// 2026-07-28 transport: one hand-off per round trip
// ---------------------------------------------------------------------------

/// The plan's position, as carried in `requestState.url_plan`.
#[derive(Serialize, Deserialize)]
pub(super) struct PlanState {
    pub(super) plan: Plan,
    pub(super) index: usize,
}

/// `input_required` asking the user to open hand-off `index`.
pub(super) fn modern_ask(ctx: &Ctx, plan: Plan, index: usize) -> Reply {
    let Some(handoff) = plan.handoffs.get(index) else {
        return fallback(&plan, Stopped::Failed);
    };
    let params = url_params(handoff, None);
    let plan_state = PlanState { plan, index };
    match mint_url_state(ctx, &plan_state) {
        Ok(token) => Reply::Result(json!({
            "resultType": "input_required",
            "inputRequests": {
                STEP_URL: { "method": "elicitation/create", "params": params },
            },
            "requestState": token,
        })),
        Err(e) => {
            tracing::error!("mint url request state failed: {e}");
            fallback(&plan_state.plan, Stopped::Failed)
        }
    }
}

/// The retry: the client answered hand-off `index`. Accepting means the user
/// is in the browser now, so the retry waits for the flow — as a deferred
/// reply, rendered as an SSE response with keep-alives — and answers with the
/// next hand-off or the result.
pub(super) fn modern_continue(ctx: Ctx, plan_state: PlanState, answer: &Value) -> Reply {
    let action = answer
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("cancel");
    let PlanState { plan, index } = plan_state;
    if action != "accept" {
        let stopped = Stopped::from_action(action);
        return Reply::Deferred(Box::pin(async move { stop(&ctx, &plan, stopped).await }));
    }
    Reply::Deferred(Box::pin(async move {
        let Some(handoff) = plan.handoffs.get(index) else {
            return stop(&ctx, &plan, Stopped::Failed).await;
        };
        let watch = handoff.watch.clone();
        match wait_for(&ctx, &watch, || async { None }).await {
            Err(stopped) => stop(&ctx, &plan, stopped).await,
            Ok(()) if index + 1 < plan.handoffs.len() => modern_ask(&ctx, plan, index + 1),
            Ok(()) => finish(&ctx, &plan).await,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only this server's own gated connect links are watchable: another
    /// origin, another path or a missing id is a link Overslash cannot see
    /// complete, so it is never turned into a hand-off.
    #[test]
    fn only_our_own_connect_links_name_a_flow() {
        let base = "https://api.overslash.test";
        assert_eq!(
            own_flow_id(base, "https://api.overslash.test/connect-authorize?id=abc").as_deref(),
            Some("abc")
        );
        assert_eq!(
            own_flow_id(
                "https://api.overslash.test/",
                "https://api.overslash.test/connect-authorize?x=1&id=abc"
            )
            .as_deref(),
            Some("abc")
        );
        for foreign in [
            "https://evil.test/connect-authorize?id=abc",
            "http://api.overslash.test/connect-authorize?id=abc",
            "https://api.overslash.test/gated-authorize?id=abc",
            "https://api.overslash.test/connect-authorize?id=",
            "https://api.overslash.test/connect-authorize",
            "https://oversla.sh/xy7",
            "not a url",
        ] {
            assert_eq!(own_flow_id(base, foreign), None, "{foreign}");
        }
    }

    #[test]
    fn url_support_needs_the_url_mode_declared() {
        assert!(supports_url_elicitation(
            &json!({ "elicitation": { "url": {} } })
        ));
        assert!(supports_url_elicitation(
            &json!({ "elicitation": { "form": {}, "url": {} } })
        ));
        assert!(!supports_url_elicitation(&json!({ "elicitation": {} })));
        assert!(!supports_url_elicitation(
            &json!({ "elicitation": { "form": {} } })
        ));
        assert!(!supports_url_elicitation(&json!({})));
    }

    #[test]
    fn a_note_is_added_without_disturbing_the_body() {
        let body = json!({ "error": "needs_authentication", "auth_url": "https://x" });
        let noted = with_note(&body, "declined");
        assert_eq!(noted["url_elicitation"], "declined");
        assert_eq!(noted["auth_url"], "https://x");
        assert_eq!(
            with_note(&json!([1]), "failed"),
            json!({ "result": [1], "url_elicitation": "failed" })
        );
    }

    #[test]
    fn legacy_params_carry_the_elicitation_id_and_modern_ones_do_not() {
        let h = Handoff {
            url: "https://api.example/connect-authorize?id=f1".into(),
            message: "Connect".into(),
            watch: Watch::OauthFlow { id: "f1".into() },
        };
        let legacy = url_params(&h, Some("elicit_url_1"));
        assert_eq!(legacy["mode"], "url");
        assert_eq!(legacy["elicitationId"], "elicit_url_1");
        assert!(url_params(&h, None).get("elicitationId").is_none());
    }

    #[test]
    fn an_approval_plans_its_own_page_and_calls_on_completion() {
        let env = json!({
            "status": "pending_approval",
            "approval_id": "11111111-1111-1111-1111-111111111111",
            "approval_url": "https://app.example/approvals/1111",
            "action_description": "send an email",
        });
        let plan = plan_for_approval(&env).unwrap();
        assert_eq!(plan.then, Then::CallApproval);
        assert_eq!(plan.handoffs[0].url, "https://app.example/approvals/1111");
        assert!(plan.handoffs[0].message.contains("send an email"));
        assert!(!plan.fallback_is_error);
    }

    #[test]
    fn plan_state_round_trips_through_json() {
        let plan = Plan {
            handoffs: vec![Handoff {
                url: "u".into(),
                message: "m".into(),
                watch: Watch::SecretRequest { id: "req_1".into() },
            }],
            then: Then::Report,
            fallback: json!({ "a": 1 }),
            fallback_is_error: false,
            approval_row: None,
        };
        let v = serde_json::to_value(PlanState { plan, index: 0 }).unwrap();
        let back: PlanState = serde_json::from_value(v).unwrap();
        assert_eq!(back.plan.then, Then::Report);
        assert_eq!(
            back.plan.handoffs[0].watch,
            Watch::SecretRequest { id: "req_1".into() }
        );
    }
}
