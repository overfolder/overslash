use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::client::ClientInner;
use crate::sse::SseEventStream;

#[derive(Debug, Clone)]
pub enum Auth {
    None,
    Bearer(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientCaps {
    #[serde(default)]
    pub elicitation: bool,
    #[serde(default)]
    pub sampling: bool,
    #[serde(default)]
    pub roots: bool,
}

impl ClientCaps {
    pub fn to_capabilities_value(&self) -> Value {
        let mut obj = serde_json::Map::new();
        if self.elicitation {
            obj.insert("elicitation".into(), Value::Object(Default::default()));
        }
        if self.sampling {
            obj.insert("sampling".into(), Value::Object(Default::default()));
        }
        if self.roots {
            obj.insert("roots".into(), Value::Object(Default::default()));
        }
        Value::Object(obj)
    }
}

pub struct ConnectOpts {
    pub base_url: Url,
    pub auth: Auth,
    pub declare_capabilities: ClientCaps,
    /// Protocol version sent on `initialize`. Default: `"2025-06-18"` (matches
    /// the version Overslash advertises). Override for compat tests.
    pub protocol_version: Option<String>,
    /// Client info sent on `initialize`. Defaults to `{name:"overslash-mcp-puppet",version:"0.1.0"}`.
    pub client_info: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct InitializeResult {
    pub protocol_version: String,
    pub server_capabilities: Value,
    pub server_info: Value,
    pub session_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CallToolOpts {
    /// Pre-canned answers, dequeued in arrival order as `elicitation/create`
    /// events stream in. Empty = pure interactive mode (call_tool returns
    /// `Suspended` on the first elicitation).
    #[serde(default)]
    pub elicitations: VecDeque<ElicitationAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationAnswer {
    /// One of `"accept"`, `"decline"`, `"cancel"`.
    pub action: String,
    /// Form data for `accept`, optional otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationRequest {
    /// `"elicit_<uuid>"` — the JSON-RPC id the client must echo on its answer.
    pub id: String,
    pub message: String,
    #[serde(rename = "requestedSchema")]
    pub requested_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandledElicitation {
    pub request: ElicitationRequest,
    pub answer: ElicitationAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Outcome of a `tools/call` step. Either the call ran to completion (`Final`)
/// or the server emitted an `elicitation/create` request that the per-call
/// queue couldn't service (`Suspended`).
pub enum CallStep {
    Final {
        result: Option<Value>,
        error: Option<JsonRpcError>,
        elicitations: Vec<HandledElicitation>,
    },
    Suspended(SuspendedCall),
}

/// A `tools/call` that's blocked on an elicitation answer the queue couldn't
/// supply. Owns the still-open SSE response so resuming continues the *same*
/// stream rather than re-issuing the request.
pub struct SuspendedCall {
    pub(crate) inner: std::sync::Arc<ClientInner>,
    pub(crate) rpc_id: Value,
    pub(crate) elicitation_request: ElicitationRequest,
    pub(crate) handled: Vec<HandledElicitation>,
    pub(crate) queue: VecDeque<ElicitationAnswer>,
    pub(crate) stream: SseEventStream,
}

impl SuspendedCall {
    pub fn request(&self) -> &ElicitationRequest {
        &self.elicitation_request
    }
}
