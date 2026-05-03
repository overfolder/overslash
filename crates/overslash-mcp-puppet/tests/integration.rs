//! Integration tests for `PuppetClient` against a tiny in-test mock MCP
//! server. The mock speaks just enough of Streamable HTTP + JSON-RPC to
//! exercise the puppet's state machine — initialize, tools/call (JSON), SSE
//! tools/call with elicitation, bare-response answer delivery, and the
//! suspend/resume path.
//!
//! Real-API wire-format compatibility is exercised by the Playwright e2e
//! specs under `dashboard/tests/e2e/scenarios/mcp-*.spec.ts`, which run the
//! puppet against a live Overslash stack via the REST surface.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, http::StatusCode};
use dashmap::DashMap;
use futures_util::stream::Stream;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

use overslash_mcp_puppet::{
    Auth, CallStep, CallToolOpts, ClientCaps, ConnectOpts, ElicitationAnswer, PuppetClient,
};

#[derive(Clone)]
struct MockState {
    /// elicit_id → sender that fires when the bare-response answer POSTs
    /// arrive. The SSE handler waits on the receiver and then emits the
    /// final result event.
    pending: Arc<DashMap<String, oneshot::Sender<Value>>>,
}

async fn handle_mcp(State(state): State<MockState>, _headers: HeaderMap, body: String) -> Response {
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "parse").into_response(),
    };

    // Bare-response delivery (elicitation answer).
    if parsed.get("method").is_none() {
        if let Some(id) = parsed.get("id").and_then(Value::as_str) {
            if id.starts_with("elicit_") {
                if let Some((_, tx)) = state.pending.remove(id) {
                    let result = parsed.get("result").cloned().unwrap_or(Value::Null);
                    let _ = tx.send(result);
                }
                return (StatusCode::ACCEPTED, "").into_response();
            }
        }
        return (StatusCode::BAD_REQUEST, "unknown bare response").into_response();
    }

    let method = parsed.get("method").and_then(Value::as_str).unwrap_or("");
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => {
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {}, "elicitation": {} },
                    "serverInfo": { "name": "mock-mcp", "version": "0.0.0" }
                }
            });
            (
                StatusCode::OK,
                [("Mcp-Session-Id", "session-123")],
                Json(body),
            )
                .into_response()
        }
        "tools/list" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": [{ "name": "echo" }] }
        }))
        .into_response(),
        "tools/call" => {
            let name = parsed
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            match name {
                // Synchronous JSON happy path.
                "echo" => {
                    let args = parsed
                        .get("params")
                        .and_then(|p| p.get("arguments"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{ "type": "text", "text": format!("echo:{args}") }]
                        }
                    }))
                    .into_response()
                }
                // SSE: elicitation/create, wait for answer, then final result event.
                "needs_one_elicitation" => {
                    let elicit_id = format!("elicit_{}", uuid::Uuid::new_v4());
                    let (tx, rx) = oneshot::channel::<Value>();
                    state.pending.insert(elicit_id.clone(), tx);
                    sse_with_one_elicitation(id, elicit_id, rx)
                }
                "needs_two_elicitations" => {
                    let id1 = format!("elicit_{}", uuid::Uuid::new_v4());
                    let id2 = format!("elicit_{}", uuid::Uuid::new_v4());
                    let (tx1, rx1) = oneshot::channel::<Value>();
                    let (tx2, rx2) = oneshot::channel::<Value>();
                    state.pending.insert(id1.clone(), tx1);
                    state.pending.insert(id2.clone(), tx2);
                    sse_with_two_elicitations(id, id1, id2, rx1, rx2)
                }
                _ => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "unknown tool" }
                }))
                .into_response(),
            }
        }
        _ => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "unknown method" }
        }))
        .into_response(),
    }
}

fn sse_with_one_elicitation(
    rpc_id: Value,
    elicit_id: String,
    rx: oneshot::Receiver<Value>,
) -> Response {
    let elicit_event = json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "method": "elicitation/create",
        "params": {
            "message": "approve?",
            "requestedSchema": { "type": "object", "properties": { "decision": { "type": "string" } }, "required": ["decision"] }
        }
    });
    let stream = make_sse_stream(rpc_id, vec![elicit_event], vec![rx], false);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn sse_with_two_elicitations(
    rpc_id: Value,
    id1: String,
    id2: String,
    rx1: oneshot::Receiver<Value>,
    rx2: oneshot::Receiver<Value>,
) -> Response {
    let evt1 = json!({
        "jsonrpc": "2.0",
        "id": id1,
        "method": "elicitation/create",
        "params": { "message": "first", "requestedSchema": {} }
    });
    let evt2 = json!({
        "jsonrpc": "2.0",
        "id": id2,
        "method": "elicitation/create",
        "params": { "message": "second", "requestedSchema": {} }
    });
    let stream = make_sse_stream(rpc_id, vec![evt1, evt2], vec![rx1, rx2], true);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Build an SSE stream that emits each elicit event, awaits the matching
/// answer, then emits a final response event echoing all answers.
///
/// `interleave_after_each_answer` controls ordering: when true (multi-elicit
/// case) we emit elicit_n, await answer_n, emit elicit_{n+1}, etc. — this
/// matches Overslash's actual behaviour (one elicitation in flight at a
/// time). When false (single elicit case), the order is still elicit, await,
/// final.
fn make_sse_stream(
    rpc_id: Value,
    events: Vec<Value>,
    answers: Vec<oneshot::Receiver<Value>>,
    interleave_after_each_answer: bool,
) -> impl Stream<Item = Result<Event, Infallible>> {
    use futures_util::stream::unfold;

    enum Step {
        Emit(Value),
        Await(oneshot::Receiver<Value>),
        Final,
        Done,
    }

    // Build the script.
    let mut script: Vec<Step> = Vec::new();
    let mut events_iter = events.into_iter();
    let mut answers_iter = answers.into_iter();
    if interleave_after_each_answer {
        for ev in events_iter.by_ref() {
            script.push(Step::Emit(ev));
            if let Some(rx) = answers_iter.next() {
                script.push(Step::Await(rx));
            }
        }
    } else {
        for ev in events_iter {
            script.push(Step::Emit(ev));
        }
        for rx in answers_iter {
            script.push(Step::Await(rx));
        }
    }
    script.push(Step::Final);
    script.push(Step::Done);

    let answers_collected: Vec<Value> = Vec::new();
    let st = (script.into_iter(), answers_collected, rpc_id);
    unfold(st, |(mut script, mut answers, rpc_id)| async move {
        loop {
            match script.next()? {
                Step::Emit(value) => {
                    let ev = Event::default().json_data(value).unwrap();
                    return Some((Ok::<_, Infallible>(ev), (script, answers, rpc_id)));
                }
                Step::Await(rx) => match rx.await {
                    Ok(v) => answers.push(v),
                    Err(_) => return None,
                },
                Step::Final => {
                    let ev = json!({
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "content": [{ "type": "text", "text": "ok" }],
                            "answers_received": answers,
                        }
                    });
                    let ev = Event::default().json_data(ev).unwrap();
                    return Some((Ok::<_, Infallible>(ev), (script, answers, rpc_id)));
                }
                Step::Done => return None,
            }
        }
    })
}

async fn spawn_mock() -> Url {
    let state = MockState {
        pending: Arc::new(DashMap::new()),
    };
    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Url::parse(&format!("http://{addr}")).unwrap()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_captures_server_info_and_session_id() {
    let url = spawn_mock().await;
    let (client, init) = PuppetClient::connect(ConnectOpts {
        base_url: url.clone(),
        auth: Auth::None,
        declare_capabilities: ClientCaps {
            elicitation: true,
            ..Default::default()
        },
        protocol_version: None,
        client_info: None,
    })
    .await
    .unwrap();

    assert_eq!(init.server_info["name"], "mock-mcp");
    assert!(init.server_capabilities.get("elicitation").is_some());
    assert_eq!(init.session_id.as_deref(), Some("session-123"));

    let tools = client.list_tools().await.unwrap();
    assert_eq!(tools["tools"][0]["name"], "echo");
}

#[tokio::test]
async fn call_tool_synchronous_returns_final() {
    let url = spawn_mock().await;
    let (client, _) = PuppetClient::connect(ConnectOpts {
        base_url: url,
        auth: Auth::None,
        declare_capabilities: Default::default(),
        protocol_version: None,
        client_info: None,
    })
    .await
    .unwrap();

    let step = client
        .call_tool("echo", json!({"hi": 1}), Default::default())
        .await
        .unwrap();
    let CallStep::Final {
        result,
        error,
        elicitations,
    } = step
    else {
        panic!("expected Final");
    };
    assert!(error.is_none());
    assert!(elicitations.is_empty());
    let text = result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.starts_with("echo:"), "got {text}");
}

#[tokio::test]
async fn call_tool_sse_with_scripted_answer_returns_final() {
    let url = spawn_mock().await;
    let (client, _) = PuppetClient::connect(ConnectOpts {
        base_url: url,
        auth: Auth::None,
        declare_capabilities: ClientCaps {
            elicitation: true,
            ..Default::default()
        },
        protocol_version: None,
        client_info: None,
    })
    .await
    .unwrap();

    let mut q = VecDeque::new();
    q.push_back(ElicitationAnswer {
        action: "accept".into(),
        content: Some(json!({ "decision": "allow" })),
    });

    let step = client
        .call_tool(
            "needs_one_elicitation",
            json!({}),
            CallToolOpts { elicitations: q },
        )
        .await
        .unwrap();
    let CallStep::Final {
        result,
        elicitations,
        ..
    } = step
    else {
        panic!("expected Final");
    };
    assert_eq!(elicitations.len(), 1);
    assert_eq!(elicitations[0].answer.action, "accept");
    let answers = &result.unwrap()["answers_received"];
    assert_eq!(answers[0]["action"], "accept");
    assert_eq!(answers[0]["content"]["decision"], "allow");
}

#[tokio::test]
async fn call_tool_sse_empty_queue_yields_suspended_then_resumes() {
    let url = spawn_mock().await;
    let (client, _) = PuppetClient::connect(ConnectOpts {
        base_url: url,
        auth: Auth::None,
        declare_capabilities: ClientCaps {
            elicitation: true,
            ..Default::default()
        },
        protocol_version: None,
        client_info: None,
    })
    .await
    .unwrap();

    let step = client
        .call_tool("needs_one_elicitation", json!({}), Default::default())
        .await
        .unwrap();
    let suspended = match step {
        CallStep::Suspended(s) => s,
        _ => panic!("expected Suspended"),
    };
    assert_eq!(suspended.request().message, "approve?");

    let step = suspended
        .resume(ElicitationAnswer {
            action: "accept".into(),
            content: Some(json!({"decision": "allow"})),
        })
        .await
        .unwrap();
    let CallStep::Final { elicitations, .. } = step else {
        panic!("expected Final after resume");
    };
    assert_eq!(elicitations.len(), 1);
}

#[tokio::test]
async fn call_tool_sse_two_elicitations_consume_queue_in_order() {
    let url = spawn_mock().await;
    let (client, _) = PuppetClient::connect(ConnectOpts {
        base_url: url,
        auth: Auth::None,
        declare_capabilities: ClientCaps {
            elicitation: true,
            ..Default::default()
        },
        protocol_version: None,
        client_info: None,
    })
    .await
    .unwrap();

    let mut q = VecDeque::new();
    q.push_back(ElicitationAnswer {
        action: "accept".into(),
        content: Some(json!({"n": 1})),
    });
    q.push_back(ElicitationAnswer {
        action: "decline".into(),
        content: None,
    });

    let step = client
        .call_tool(
            "needs_two_elicitations",
            json!({}),
            CallToolOpts { elicitations: q },
        )
        .await
        .unwrap();
    let CallStep::Final { elicitations, .. } = step else {
        panic!("expected Final");
    };
    assert_eq!(elicitations.len(), 2);
    assert_eq!(elicitations[0].answer.action, "accept");
    assert_eq!(elicitations[1].answer.action, "decline");
}
