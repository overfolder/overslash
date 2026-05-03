//! `PuppetClient` — drives the MCP wire protocol over Streamable HTTP.
//!
//! The state machine is shared by `call_tool` and `SuspendedCall::resume`:
//!
//! 1. Initial `call_tool` POSTs `tools/call` to `/mcp` with
//!    `Accept: application/json, text/event-stream`.
//!    - JSON response → return `CallStep::Final` immediately.
//!    - SSE response → enter the read loop with the per-call elicitation
//!      queue.
//! 2. Read loop:
//!    - On `elicitation/create`: pop the next queue entry. If present, post
//!      it as a bare JSON-RPC response back to `/mcp`, record `(req,answer)`,
//!      keep reading. If empty, return `CallStep::Suspended` carrying the
//!      request and a `resume` future that owns the still-open stream.
//!    - On the response event matching the original request id: return
//!      `CallStep::Final` with the streamed `result`/`error` and the
//!      recorded elicitations.
//! 3. `resume(answer)`: post the answer back to `/mcp`, record it, re-enter
//!    the read loop with whatever queue is left.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::sse::SseEventStream;
use crate::types::{
    Auth, CallStep, CallToolOpts, ConnectOpts, ElicitationAnswer, ElicitationRequest,
    HandledElicitation, InitializeResult, JsonRpcError, SuspendedCall,
};

const MCP_SESSION_HEADER: &str = "Mcp-Session-Id";

pub struct ClientInner {
    pub(crate) base_url: Url,
    pub(crate) http: reqwest::Client,
    pub(crate) auth: Auth,
    pub(crate) session_id: Mutex<Option<String>>,
}

impl ClientInner {
    fn mcp_url(&self) -> Result<Url> {
        Ok(self.base_url.join("/mcp")?)
    }

    fn build_headers(&self, accept_sse: bool) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let accept = if accept_sse {
            "application/json, text/event-stream"
        } else {
            "application/json"
        };
        h.insert(ACCEPT, HeaderValue::from_static(accept));
        if let Auth::Bearer(token) = &self.auth {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                h.insert(AUTHORIZATION, v);
            }
        }
        if let Ok(guard) = self.session_id.lock() {
            if let Some(sid) = guard.as_deref() {
                if let Ok(v) = HeaderValue::from_str(sid) {
                    h.insert(MCP_SESSION_HEADER, v);
                }
            }
        }
        h
    }

    fn record_session_id(&self, resp_headers: &HeaderMap) {
        if let Some(sid) = resp_headers
            .get(MCP_SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(mut guard) = self.session_id.lock() {
                *guard = Some(sid.to_string());
            }
        }
    }
}

#[derive(Clone)]
pub struct PuppetClient {
    pub(crate) inner: Arc<ClientInner>,
}

impl PuppetClient {
    pub async fn connect(opts: ConnectOpts) -> Result<(Self, InitializeResult)> {
        let inner = Arc::new(ClientInner {
            base_url: opts.base_url,
            http: reqwest::Client::new(),
            auth: opts.auth,
            session_id: Mutex::new(None),
        });

        let protocol_version = opts
            .protocol_version
            .unwrap_or_else(|| "2025-06-18".to_string());
        let client_info = opts.client_info.unwrap_or_else(
            || json!({ "name": "overslash-mcp-puppet", "version": env!("CARGO_PKG_VERSION") }),
        );

        let body = json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": opts.declare_capabilities.to_capabilities_value(),
                "clientInfo": client_info,
            }
        });

        let resp = inner
            .http
            .post(inner.mcp_url()?)
            .headers(inner.build_headers(false))
            .body(body.to_string())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::Status {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        inner.record_session_id(resp.headers());

        let body: Value = resp.json().await?;
        let result = body
            .get("result")
            .ok_or_else(|| Error::UnexpectedResponse("initialize missing result".into()))?;
        let server_capabilities = result
            .get("capabilities")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        let server_info = result.get("serverInfo").cloned().unwrap_or(Value::Null);
        let pv = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(&protocol_version)
            .to_string();
        let session_id = inner
            .session_id
            .lock()
            .ok()
            .and_then(|g| g.as_ref().cloned());

        // Per MCP spec: clients MUST send `notifications/initialized` after a
        // successful initialize handshake to signal end-of-init. Strict
        // servers reject `tools/list` / `tools/call` until they see it.
        // Fire-and-forget; failures here don't invalidate the session.
        let notify = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        });
        let _ = inner
            .http
            .post(inner.mcp_url()?)
            .headers(inner.build_headers(false))
            .body(notify.to_string())
            .send()
            .await;

        Ok((
            Self {
                inner: inner.clone(),
            },
            InitializeResult {
                protocol_version: pv,
                server_capabilities,
                server_info,
                session_id,
            },
        ))
    }

    pub async fn list_tools(&self) -> Result<Value> {
        self.simple_rpc("tools/list", json!({})).await
    }

    pub async fn list_resources(&self) -> Result<Value> {
        self.simple_rpc("resources/list", json!({})).await
    }

    /// Issue a `tools/call`. The returned `CallStep` is either `Final` (the
    /// call finished, with or without elicitations along the way) or
    /// `Suspended` (an elicitation arrived with no answer queued — the
    /// caller drives the rest with `SuspendedCall::resume`).
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
        opts: CallToolOpts,
    ) -> Result<CallStep> {
        let rpc_id = Value::String(Uuid::new_v4().to_string());
        let body = json!({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });

        let resp = self
            .inner
            .http
            .post(self.inner.mcp_url()?)
            .headers(self.inner.build_headers(true))
            .body(body.to_string())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::Status {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let is_sse = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.starts_with("text/event-stream"))
            .unwrap_or(false);

        if !is_sse {
            let body: Value = resp.json().await?;
            return Ok(parse_final_jsonrpc(body, &rpc_id, Vec::new()));
        }

        let stream = SseEventStream::from_reqwest(resp);
        run_sse_loop(
            self.inner.clone(),
            rpc_id,
            stream,
            Vec::new(),
            opts.elicitations,
        )
        .await
    }

    async fn simple_rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": method,
            "params": params,
        });
        let resp = self
            .inner
            .http
            .post(self.inner.mcp_url()?)
            .headers(self.inner.build_headers(false))
            .body(body.to_string())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::Status {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        let body: Value = resp.json().await?;
        Ok(body.get("result").cloned().unwrap_or(Value::Null))
    }
}

impl SuspendedCall {
    pub async fn resume(self, answer: ElicitationAnswer) -> Result<CallStep> {
        let SuspendedCall {
            inner,
            rpc_id,
            elicitation_request,
            mut handled,
            queue,
            stream,
        } = self;

        post_elicitation_answer(&inner, &elicitation_request.id, &answer).await?;
        handled.push(HandledElicitation {
            request: elicitation_request,
            answer,
        });
        run_sse_loop(inner, rpc_id, stream, handled, queue).await
    }
}

async fn run_sse_loop(
    inner: Arc<ClientInner>,
    rpc_id: Value,
    mut stream: SseEventStream,
    mut handled: Vec<HandledElicitation>,
    mut queue: VecDeque<ElicitationAnswer>,
) -> Result<CallStep> {
    loop {
        let Some(event) = stream.next_event().await? else {
            return Err(Error::PrematureStreamEnd);
        };

        // Elicitation request from the server?
        if event.get("method").and_then(Value::as_str) == Some("elicitation/create") {
            let elicit_id = event
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::UnexpectedResponse("elicitation/create missing id".into()))?
                .to_string();
            let params = event.get("params").cloned().unwrap_or(Value::Null);
            let request = parse_elicitation_request(&elicit_id, &params)?;

            if let Some(answer) = queue.pop_front() {
                post_elicitation_answer(&inner, &request.id, &answer).await?;
                handled.push(HandledElicitation { request, answer });
                continue;
            }

            return Ok(CallStep::Suspended(SuspendedCall {
                inner,
                rpc_id,
                elicitation_request: request,
                handled,
                queue,
                stream,
            }));
        }

        // Final response event? Match by jsonrpc id.
        if event.get("id") == Some(&rpc_id) {
            return Ok(parse_final_jsonrpc(event, &rpc_id, handled));
        }

        // Other server-to-client requests aren't supported yet (no sampling,
        // no roots). Skip silently rather than fail — gives forward compat.
        tracing::debug!(?event, "puppet skipping unrecognised SSE event");
    }
}

async fn post_elicitation_answer(
    inner: &Arc<ClientInner>,
    elicit_id: &str,
    answer: &ElicitationAnswer,
) -> Result<()> {
    let mut body = json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "result": {
            "action": answer.action,
        },
    });
    if let Some(content) = &answer.content {
        body["result"]["content"] = content.clone();
    }
    let resp = inner
        .http
        .post(inner.mcp_url()?)
        .headers(inner.build_headers(false))
        .body(body.to_string())
        .send()
        .await?;
    if !resp.status().is_success() && resp.status().as_u16() != 202 {
        return Err(Error::Status {
            status: resp.status().as_u16(),
            body: resp.text().await.unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_elicitation_request(id: &str, params: &Value) -> Result<ElicitationRequest> {
    let message = params
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let requested_schema = params
        .get("requestedSchema")
        .cloned()
        .unwrap_or(Value::Null);
    let meta = params.get("_meta").cloned();
    Ok(ElicitationRequest {
        id: id.to_string(),
        message,
        requested_schema,
        meta,
    })
}

fn parse_final_jsonrpc(
    body: Value,
    expected_id: &Value,
    elicitations: Vec<HandledElicitation>,
) -> CallStep {
    // Best-effort id check — if the server returned a payload without id,
    // accept it; the SSE stream context already disambiguated.
    if let Some(id) = body.get("id") {
        if id != expected_id {
            tracing::debug!(?id, ?expected_id, "puppet final response id mismatch");
        }
    }
    let result = body.get("result").cloned();
    let error = body.get("error").map(|e| JsonRpcError {
        code: e.get("code").and_then(Value::as_i64).unwrap_or(0) as i32,
        message: e
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        data: e.get("data").cloned(),
    });
    CallStep::Final {
        result,
        error,
        elicitations,
    }
}
