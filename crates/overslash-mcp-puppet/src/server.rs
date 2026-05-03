//! REST wrapper around `PuppetClient`. The harness boots this on a dynamic
//! port; Playwright tests drive the puppet through the REST surface so the
//! TS side never reimplements MCP wire format.
//!
//! Sessions are keyed by an opaque `session_id`. Suspended calls are parked
//! in a separate `DashMap<call_token, SuspendedCall>` so the puppet REST
//! handler can return immediately when an elicitation arrives, and the
//! caller can drive the answer via `POST /sessions/:id/calls/:token/resume`.
//!
//! See `crates/overslash-mcp-puppet/src/bin/overslash-mcp-puppet.rs` for the
//! binary entrypoint.

use std::collections::VecDeque;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, post},
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::client::PuppetClient;
use crate::types::{
    Auth, CallStep, CallToolOpts, ClientCaps, ConnectOpts, ElicitationAnswer, ElicitationRequest,
    HandledElicitation, JsonRpcError, SuspendedCall,
};

/// Parked suspended calls live behind a `tokio::sync::Mutex<Option<_>>` so the
/// DashMap value is `Sync` (the SSE stream inside `SuspendedCall` is `Send`
/// but not `Sync`). The Option holds None once `resume` has consumed the
/// call, defending against double-resume races.
type ParkedCall = tokio::sync::Mutex<Option<SuspendedCall>>;

#[derive(Clone)]
pub struct AppState {
    sessions: Arc<DashMap<String, PuppetClient>>,
    parked: Arc<DashMap<String, Arc<ParkedCall>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            parked: Arc::new(DashMap::new()),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn router() -> Router {
    let state = AppState::new();
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions/{id}", delete(close_session))
        .route("/sessions/{id}/tools/list", post(tools_list))
        .route("/sessions/{id}/tools/call", post(tools_call))
        .route("/sessions/{id}/resources/list", post(resources_list))
        .route("/sessions/{id}/calls/{token}/resume", post(resume_call))
        .with_state(state)
}

// ─── DTOs ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AuthDto {
    /// `"none"` | `"bearer"`.
    kind: String,
    #[serde(default)]
    value: Option<String>,
}

impl AuthDto {
    fn into_auth(self) -> Result<Auth, AppErr> {
        match self.kind.as_str() {
            "none" => Ok(Auth::None),
            "bearer" => self
                .value
                .ok_or_else(|| AppErr::bad_request("auth.kind=bearer requires value"))
                .map(Auth::Bearer),
            other => Err(AppErr::bad_request(format!(
                "auth.kind must be 'none' or 'bearer', got '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateSessionReq {
    base_url: String,
    auth: AuthDto,
    #[serde(default)]
    declare_capabilities: ClientCaps,
    #[serde(default)]
    protocol_version: Option<String>,
    #[serde(default)]
    client_info: Option<Value>,
}

#[derive(Debug, Serialize)]
struct CreateSessionResp {
    session_id: String,
    server_capabilities: Value,
    server_info: Value,
    protocol_version: String,
}

#[derive(Debug, Deserialize)]
struct ToolsCallReq {
    name: String,
    #[serde(default)]
    arguments: Value,
    #[serde(default)]
    elicitations: VecDeque<ElicitationAnswer>,
}

#[derive(Debug, Deserialize)]
struct ResumeReq {
    answer: ElicitationAnswer,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum CallStepDto {
    Final {
        result: Option<Value>,
        error: Option<JsonRpcError>,
        elicitations: Vec<HandledElicitation>,
    },
    Suspended {
        call_token: String,
        request: ElicitationRequest,
    },
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionReq>,
) -> Result<Json<CreateSessionResp>, AppErr> {
    let base_url = Url::parse(&req.base_url)
        .map_err(|e| AppErr::bad_request(format!("invalid base_url: {e}")))?;
    let auth = req.auth.into_auth()?;
    let opts = ConnectOpts {
        base_url,
        auth,
        declare_capabilities: req.declare_capabilities,
        protocol_version: req.protocol_version,
        client_info: req.client_info,
    };
    let (client, init) = PuppetClient::connect(opts).await.map_err(AppErr::from)?;
    let session_id = format!("ps_{}", Uuid::new_v4());
    state.sessions.insert(session_id.clone(), client);
    Ok(Json(CreateSessionResp {
        session_id,
        server_capabilities: init.server_capabilities,
        server_info: init.server_info,
        protocol_version: init.protocol_version,
    }))
}

async fn close_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppErr> {
    state.sessions.remove(&id);
    // Also drop any parked calls for this session. Token format is
    // `ct_<uuid>`, not session-prefixed; instead we'd need a map. For v1,
    // closing a session leaves parked calls in place — they'll get GC'd by
    // TTL (TODO) or the next process restart. Acceptable trade-off for tests.
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn tools_list(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppErr> {
    let client = client_for(&state, &id)?;
    Ok(Json(client.list_tools().await.map_err(AppErr::from)?))
}

async fn resources_list(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppErr> {
    let client = client_for(&state, &id)?;
    Ok(Json(client.list_resources().await.map_err(AppErr::from)?))
}

async fn tools_call(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ToolsCallReq>,
) -> Result<Json<CallStepDto>, AppErr> {
    let client = client_for(&state, &id)?;
    let opts = CallToolOpts {
        elicitations: req.elicitations,
    };
    let step = client
        .call_tool(&req.name, req.arguments, opts)
        .await
        .map_err(AppErr::from)?;
    Ok(Json(park_step(&state, step)))
}

async fn resume_call(
    State(state): State<AppState>,
    Path((_session_id, token)): Path<(String, String)>,
    Json(req): Json<ResumeReq>,
) -> Result<Json<CallStepDto>, AppErr> {
    let parked = state
        .parked
        .remove(&token)
        .map(|(_, v)| v)
        .ok_or_else(|| AppErr::not_found(format!("no parked call with token {token}")))?;
    let suspended = parked
        .lock()
        .await
        .take()
        .ok_or_else(|| AppErr::bad_request("parked call already resumed"))?;
    let step = suspended.resume(req.answer).await.map_err(AppErr::from)?;
    Ok(Json(park_step(&state, step)))
}

fn park_step(state: &AppState, step: CallStep) -> CallStepDto {
    match step {
        CallStep::Final {
            result,
            error,
            elicitations,
        } => CallStepDto::Final {
            result,
            error,
            elicitations,
        },
        CallStep::Suspended(s) => {
            let token = format!("ct_{}", Uuid::new_v4());
            let request = s.request().clone();
            state
                .parked
                .insert(token.clone(), Arc::new(tokio::sync::Mutex::new(Some(s))));
            CallStepDto::Suspended {
                call_token: token,
                request,
            }
        }
    }
}

fn client_for(state: &AppState, id: &str) -> Result<PuppetClient, AppErr> {
    state
        .sessions
        .get(id)
        .map(|r| r.value().clone())
        .ok_or_else(|| AppErr::not_found(format!("unknown session_id {id}")))
}

// ─── Error mapping ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct AppErr {
    status: StatusCode,
    body: Value,
}

impl AppErr {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::json!({ "error": msg.into() }),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: serde_json::json!({ "error": msg.into() }),
        }
    }
}

impl From<crate::error::Error> for AppErr {
    fn from(e: crate::error::Error) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            body: serde_json::json!({ "error": e.to_string() }),
        }
    }
}

impl IntoResponse for AppErr {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self.body)).into_response()
    }
}
