//! Integration tests for proxy uploads — minting a capability to push bytes,
//! redeeming it, and the media ledger that lets a later approval describe what
//! was pushed.
//!
//! The inbound mirror of `downloads.rs`, and the tests are shaped around the
//! places this design can fail *silently* rather than around the happy path:
//!
//!   * the gated path, where a `risk: write` upload is replayed from a stored
//!     payload after approval and must mint rather than dispatch a tool call;
//!   * single-use redemption, where a second push under one authorization is
//!     the whole thing the token shape exists to prevent;
//!   * content binding, where a mismatch must withhold the reference rather
//!     than merely log;
//!   * the ledger, where a descriptor seen *without* `deliver: "url"` is the
//!     common case and the easy one to miss.

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::net::TcpListener;

// ── A stub that plays both halves, as the real container does ───────────
//
// `/mcp` for the tool calls and `POST /media` for the bytes, behind the same
// bearer. The gateway must present that bearer on the byte route having
// re-resolved it from the vault, on a request the original caller never
// authenticated.

const UPLOAD_SHA: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
const UPLOAD_BODY: &[u8] = b"hello world";

#[derive(Default)]
struct StubInner {
    /// Every `POST /media` the stub saw: (content_type, filename, body).
    uploads: Vec<(Option<String>, Option<String>, Vec<u8>)>,
    /// Tool names dispatched over `/mcp`. A gateway-served action must never
    /// appear here.
    tool_calls: Vec<String>,
}

#[derive(Clone, Default)]
struct Stub {
    inner: Arc<Mutex<StubInner>>,
}

async fn media_upload(
    State(stub): State<Stub>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v != "Bearer stub-token")
    {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let filename = query.as_deref().and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "stored_as")
            .map(|(_, v)| v.to_string())
    });
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let digest = {
        use sha2::{Digest, Sha256};
        let d: [u8; 32] = Sha256::digest(&body).into();
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    stub.inner.lock().unwrap().uploads.push((
        content_type.clone(),
        filename.clone(),
        body.to_vec(),
    ));

    // Content-addressed, exactly as the real container is.
    (
        StatusCode::CREATED,
        [("location", format!("/media/{digest}"))],
        Json(json!({
            "media_path": format!("/media/{digest}"),
            "mime": content_type.unwrap_or_else(|| "application/octet-stream".into()),
            "size": body.len(),
            "filename": filename.unwrap_or_else(|| format!("{}.bin", &digest[..12])),
            "sha256": digest,
        })),
    )
        .into_response()
}

async fn mcp_handler(State(stub): State<Stub>, Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub-upload", "version": "0" },
            "capabilities": {}
        }),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            stub.inner.lock().unwrap().tool_calls.push(name.clone());
            match name.as_str() {
                "download_media" => json!({
                    "content": [{ "type": "text", "text": "downloaded" }],
                    "structuredContent": {
                        "media_path": format!("/media/{UPLOAD_SHA}"),
                        "mime": "application/pdf",
                        "size": 12345,
                        "filename": "report.pdf",
                        "sha256": UPLOAD_SHA,
                    },
                    "isError": false
                }),
                _ => json!({
                    "content": [{ "type": "text", "text": "sent" }],
                    "structuredContent": { "ok": true },
                    "isError": false
                }),
            }
        }
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_stub() -> (SocketAddr, Arc<Mutex<StubInner>>) {
    common::allow_loopback_ssrf();
    let stub = Stub::default();
    let inner = stub.inner.clone();
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .route("/media", post(media_upload))
        .with_state(stub);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, inner)
}

// ── Template fixture ────────────────────────────────────────────────────

/// Mirrors the shipped `services/whatsapp.yaml` entries this feature adds:
/// `upload_media` with its `upload:` block, `download_media` with a `sha256`
/// filter, and a `send_file` whose `media_path` resolves through the ledger.
fn template_yaml(key: &str, url: &str, secret_name: &str, upload_path: &str) -> String {
    format!(
        r#"openapi: "3.1.0"
info:
  title: Upload Stub
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth: {{ kind: bearer, secret_name: {secret_name} }}
  autodiscover: false
  tools:
    - name: upload_media
      risk: write
      description: 'Mint a URL for pushing a file'
      upload:
        path: {upload_path}
        method: POST
        # Deliberately not the conventional `filename`: a fixture that reuses
        # it cannot tell a template-driven parameter name from a hardcoded one,
        # which is exactly how this shipped inert once.
        filename_param: stored_as
        auth: inherit
        max_bytes: 1024
        result:
          media_path: .media_path
          sha256: .sha256
          mime: .mime
          size: .size
          filename: .filename
      input_schema:
        type: object
        properties:
          filename: {{ type: string }}
          mime: {{ type: string }}
          size_bytes: {{ type: integer }}
          sha256: {{ type: string }}
        required: []
      disclose:
        - label: "File"
          primary: true
          filter: '.arguments.filename // "unnamed upload"'
        - label: "SHA-256"
          filter: ".arguments.sha256 // empty"
    - name: download_media
      risk: read
      description: 'Download media from {{chat_jid}}'
      download:
        url: .structured.media_path
        mime: .structured.mime
        size: .structured.size
        filename: .structured.filename
        sha256: .structured.sha256
        auth: inherit
      input_schema:
        type: object
        properties:
          chat_jid: {{ type: string }}
        required: [chat_jid]
    - name: send_file
      risk: write
      description: 'Send a file to {{recipient}}'
      input_schema:
        type: object
        properties:
          recipient: {{ type: string }}
          media_path:
            type: string
            resolve:
              source: media
              display: '{{filename}}[ ({{mime}}, {{size}} bytes)]'
        required: [recipient, media_path]
      disclose:
        - label: "File"
          primary: true
          filter: ".resolved.media_path // .arguments.media_path"
"#
    )
}

struct Fx {
    base: String,
    client: Client,
    agent_key: String,
    admin_key: String,
    stub: Arc<Mutex<StubInner>>,
}

async fn setup(pool: sqlx::PgPool) -> Fx {
    setup_with(pool, "/media", &["upstub:**"], |_| {}).await
}

/// Grants only the byte-moving actions, leaving `send_file` uncovered so it
/// bubbles an approval — a *gap* in the chain, not a deny, since a deny is
/// refused outright and never produces the disclosure a reviewer would read.
async fn setup_for_disclosure(pool: sqlx::PgPool) -> Fx {
    setup_with(
        pool,
        "/media",
        &["upstub:upload_media:**", "upstub:download_media:**"],
        |_| {},
    )
    .await
}

/// An empty `grants` leaves the agent with nothing, so its first call is gated
/// and goes down the replay path instead of the inline one.
async fn setup_with<F>(pool: sqlx::PgPool, upload_path: &str, grants: &[&str], customize: F) -> Fx
where
    F: FnOnce(&mut overslash_api::config::Config),
{
    let (stub_addr, stub) = start_stub().await;
    let stub_url = format!("http://{stub_addr}/mcp");
    let path = upload_path.replace("{PORT}", &stub_addr.port().to_string());

    let (api_addr, client) = common::start_api_with(pool, customize).await;
    let base = format!("http://{api_addr}");
    let (_org, agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let yaml = template_yaml("upstub", &stub_url, "stub_token", &path);
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    client
        .put(format!("{base}/v1/secrets/stub_token"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "value": "stub-token" }))
        .send()
        .await
        .unwrap();

    for pattern in grants {
        client
            .post(format!("{base}/v1/permissions"))
            .header(auth(&admin_key).0, auth(&admin_key).1)
            .json(&json!({
                "identity_id": agent_ident,
                "action_pattern": pattern,
                "effect": "allow",
            }))
            .send()
            .await
            .unwrap();
    }

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({ "name": "upstub", "template_key": "upstub" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "service: {:?}", resp.text().await);

    Fx {
        base,
        client,
        agent_key,
        admin_key,
        stub,
    }
}

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Call `upload_media` and return the parsed descriptor.
async fn mint(fx: &Fx, params: Value) -> Value {
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .json(&json!({ "service": "upstub", "action": "upload_media", "params": params }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "mint: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    serde_json::from_str(body["result"]["body"].as_str().expect("body string")).unwrap()
}

// ── Minting ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn mint_returns_a_url_and_never_touches_the_container() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(
        &fx,
        json!({ "filename": "hello.txt", "mime": "text/plain" }),
    )
    .await;

    let url = d["upload_url"].as_str().expect("upload_url");
    assert!(url.starts_with(&fx.base), "{url}");
    assert_eq!(d["method"], "POST");
    // The template's own ceiling, not the deployment's — a template may lower
    // the limit, and the caller is told the number that will actually bind.
    assert_eq!(d["max_bytes"], 1024);
    assert!(d["hint"].as_str().unwrap().contains("--data-binary"));

    // Nothing about the container reaches the caller. Handing over its URL or
    // its bearer is precisely what this mechanism exists to avoid.
    let text = d.to_string();
    assert!(!text.contains("stub-token"), "credential leaked: {text}");
    assert!(!text.contains("/mcp"), "instance url leaked: {text}");

    // A gateway-served action is never forwarded: `tools/call` with this name
    // would answer "unknown tool".
    let inner = fx.stub.lock().unwrap();
    assert!(inner.tool_calls.is_empty(), "{:?}", inner.tool_calls);
    assert!(inner.uploads.is_empty(), "nothing pushed yet");
}

#[tokio::test]
async fn declared_size_over_the_template_ceiling_is_refused_at_mint() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    // Refused before a token exists rather than at redemption: the caller
    // already knows the size, so there is no reason to hand back a capability
    // that cannot succeed.
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .json(&json!({
            "service": "upstub", "action": "upload_media",
            "params": { "size_bytes": 999_999 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("exceeds"));
}

#[tokio::test]
async fn an_off_origin_upload_path_is_refused() {
    let pool = common::test_pool().await;
    // A path that resolves to another host would send this instance's
    // credential — and the caller's bytes — somewhere it does not belong.
    let fx = setup_with(
        pool,
        "https://evil.example.com/media",
        &["upstub:**"],
        |_| {},
    )
    .await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .json(&json!({ "service": "upstub", "action": "upload_media", "params": {} }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error() || resp.status().is_server_error());
    let text = resp.text().await.unwrap();
    assert!(text.contains("outside the MCP server's origin"), "{text}");
}

#[tokio::test]
async fn async_execution_is_refused_for_an_upload_mint() {
    let pool = common::test_pool().await;
    // Async has to be *enabled*, or the top-of-handler "async is disabled"
    // refusal fires first and hides the rejection under test.
    let fx = setup_with(pool, "/media", &["upstub:**"], |cfg| {
        cfg.async_execution.enabled = true;
    })
    .await;

    // The capability would spend its lifetime in a queue. Same reasoning the
    // deferred-download flags already carry.
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .json(&json!({
            "service": "upstub", "action": "upload_media",
            "params": {}, "execution": "async",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("upload capability"));
}

// ── Redemption ──────────────────────────────────────────────────────────

#[tokio::test]
async fn redemption_streams_bytes_through_and_returns_the_stored_reference() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(
        &fx,
        json!({ "filename": "hello.txt", "mime": "text/plain" }),
    )
    .await;
    let url = d["upload_url"].as_str().unwrap();

    // The pushing client sends no credential of its own — the token in the URL
    // is the whole authority.
    let resp = fx
        .client
        .post(url)
        .header("content-type", "text/plain")
        .body(UPLOAD_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "push: {:?}", resp.text().await);
    let stored: Value = resp.json().await.unwrap();
    assert_eq!(stored["media_path"], format!("/media/{UPLOAD_SHA}"));
    assert_eq!(stored["sha256"], UPLOAD_SHA);

    let inner = fx.stub.lock().unwrap();
    assert_eq!(inner.uploads.len(), 1);
    let (ct, filename, body) = &inner.uploads[0];
    assert_eq!(body, UPLOAD_BODY);
    assert_eq!(ct.as_deref(), Some("text/plain"));
    // Two claims at once: the filename comes off the *token*, never off the
    // request that redeemed it — a redeemer who could choose it could get
    // approval for one name and push another under it — and it arrives under
    // the parameter name the *template* declared (`stored_as`), not a
    // hardcoded `filename`.
    assert_eq!(filename.as_deref(), Some("hello.txt"));
}

#[tokio::test]
async fn a_token_is_good_for_exactly_one_push() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(&fx, json!({ "filename": "once.txt" })).await;
    let url = d["upload_url"].as_str().unwrap();

    let first = fx.client.post(url).body(UPLOAD_BODY).send().await.unwrap();
    assert_eq!(first.status(), 201);

    // The difference from a download token, which is deliberately multi-use so
    // a dropped transfer can resume. Two pushes under one authorization would
    // mean "what the reviewer approved" had no answer.
    let second = fx
        .client
        .post(url)
        .body(b"different".as_ref())
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 404);
    assert_eq!(second.text().await.unwrap(), "unknown or expired token");

    assert_eq!(
        fx.stub.lock().unwrap().uploads.len(),
        1,
        "the second redemption must not reach the container"
    );
}

#[tokio::test]
async fn unknown_expired_and_consumed_tokens_are_indistinguishable() {
    let pool = common::test_pool().await;
    let fx = setup(pool.clone()).await;

    // Unknown.
    let unknown = fx
        .client
        .post(format!("{}/v1/uploads/{}", fx.base, "a".repeat(43)))
        .body(UPLOAD_BODY)
        .send()
        .await
        .unwrap();

    // Consumed.
    let d = mint(&fx, json!({})).await;
    let consumed_url = d["upload_url"].as_str().unwrap().to_string();
    fx.client
        .post(&consumed_url)
        .body(UPLOAD_BODY)
        .send()
        .await
        .unwrap();
    let consumed = fx
        .client
        .post(&consumed_url)
        .body(UPLOAD_BODY)
        .send()
        .await
        .unwrap();

    // Expired.
    let d = mint(&fx, json!({})).await;
    let expired_url = d["upload_url"].as_str().unwrap().to_string();
    sqlx::query!("UPDATE upload_tokens SET expires_at = now() - interval '1 hour'")
        .execute(&pool)
        .await
        .unwrap();
    let expired = fx
        .client
        .post(&expired_url)
        .body(UPLOAD_BODY)
        .send()
        .await
        .unwrap();

    // A distinguishable "expired" would confirm to someone probing that a
    // given token string was once real.
    for (label, resp) in [
        ("unknown", unknown),
        ("consumed", consumed),
        ("expired", expired),
    ] {
        assert_eq!(resp.status(), 404, "{label}");
        assert_eq!(
            resp.text().await.unwrap(),
            "unknown or expired token",
            "{label}"
        );
    }
}

#[tokio::test]
async fn deleting_the_secret_after_mint_fails_the_push_closed() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(&fx, json!({})).await;
    let url = d["upload_url"].as_str().unwrap();

    // The credential is re-resolved at redemption rather than persisted, so
    // revoking it invalidates outstanding capabilities with no sweep.
    let del = fx
        .client
        .delete(format!("{}/v1/secrets/stub_token", fx.base))
        .header(auth(&fx.admin_key).0, auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap();
    assert!(del.status().is_success(), "delete: {:?}", del.text().await);

    let resp = fx.client.post(url).body(UPLOAD_BODY).send().await.unwrap();
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "push should fail closed, got {}",
        resp.status()
    );
    assert!(
        fx.stub.lock().unwrap().uploads.is_empty(),
        "no bytes should reach the container without a credential"
    );
}

// ── Content binding ─────────────────────────────────────────────────────

#[tokio::test]
async fn a_sha256_mismatch_is_refused_and_withholds_the_reference() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(&fx, json!({ "sha256": "0".repeat(64) })).await;
    let url = d["upload_url"].as_str().unwrap();

    let resp = fx.client.post(url).body(UPLOAD_BODY).send().await.unwrap();
    assert_eq!(resp.status(), 422);
    let text = resp.text().await.unwrap();
    assert!(text.contains("content mismatch"), "{text}");

    // The bytes did reach the container — a hash is only known after the last
    // one, so the check detects rather than prevents. Withholding the
    // reference is what makes detecting it worth anything: nothing downstream
    // can name bytes it was never told the name of.
    assert!(
        !text.contains("/media/"),
        "the stored reference must not be handed back: {text}"
    );
}

#[tokio::test]
async fn a_declared_size_is_enforced_mid_stream() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(&fx, json!({ "size_bytes": 4 })).await;
    let url = d["upload_url"].as_str().unwrap();

    // Unlike the hash, an over-length transfer is *prevented*: the meter cuts
    // it, so the container never commits the overage.
    let resp = fx
        .client
        .post(url)
        .body(vec![b'x'; 512])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    assert!(
        fx.stub.lock().unwrap().uploads.is_empty(),
        "an oversized push must not land"
    );
}

#[tokio::test]
async fn a_stated_content_length_over_the_cap_is_refused_up_front() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(&fx, json!({})).await;
    let url = d["upload_url"].as_str().unwrap();

    // The template's ceiling is 1024. A stated length past it is answered
    // before a byte moves; the mid-stream meter is still the real enforcement,
    // because a chunked body states no length and a caller may state an untrue
    // one.
    let resp = fx
        .client
        .post(url)
        .body(vec![b'x'; 4096])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    assert!(fx.stub.lock().unwrap().uploads.is_empty());
}

// ── The gated path ──────────────────────────────────────────────────────

#[tokio::test]
async fn an_approved_upload_mints_on_replay_instead_of_calling_a_tool() {
    let pool = common::test_pool().await;
    let fx = setup_with(pool, "/media", &[], |_| {}).await;

    // `upload_media` is risk: write, so a gated agent's *first* call is
    // replayed from a stored payload after approval. Replay resolves nothing —
    // it holds a URL and a tool name, not an action key — so without the spec
    // riding on the payload this dispatches `tools/call {name: upload_media}`
    // and the container answers "unknown tool". That failure only appears
    // after a human has said yes, which is why it has its own test.
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .json(&json!({
            "service": "upstub", "action": "upload_media",
            "params": { "filename": "gated.txt" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        202,
        "expected an approval: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    let approval_id = body["approval_id"].as_str().expect("approval_id");

    // The approval describes what was declared — that is all there is to
    // describe, since the bytes have not been offered yet.
    let approval: Value = fx
        .client
        .get(format!("{}/v1/approvals/{approval_id}", fx.base))
        .header(auth(&fx.admin_key).0, auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let file_row = approval["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields")
        .iter()
        .find(|f| f["label"] == "File")
        .expect("File row");
    assert_eq!(file_row["value"], "gated.txt");

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/resolve", fx.base))
        .header(auth(&fx.admin_key).0, auth(&fx.admin_key).1)
        .json(&json!({ "resolution": "allow" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "replay: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "executed");

    // The replay minted rather than dispatched.
    assert!(
        fx.stub.lock().unwrap().tool_calls.is_empty(),
        "replay must not forward a gateway-served action: {:?}",
        fx.stub.lock().unwrap().tool_calls
    );

    let result = body["execution"]["result"].clone();
    let text = result.to_string();
    assert!(text.contains("/v1/uploads/"), "replay result: {text}");
}

// ── Audit ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_redemption_is_audited_with_declared_and_measured() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let d = mint(
        &fx,
        json!({ "filename": "audited.txt", "sha256": UPLOAD_SHA }),
    )
    .await;
    let url = d["upload_url"].as_str().unwrap();
    let resp = fx.client.post(url).body(UPLOAD_BODY).send().await.unwrap();
    assert_eq!(resp.status(), 201);

    let audit: Value = fx
        .client
        .get(format!("{}/v1/audit?limit=50", fx.base))
        .header(auth(&fx.admin_key).0, auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = audit["entries"]
        .as_array()
        .or_else(|| audit.as_array())
        .expect("audit entries");
    let row = entries
        .iter()
        .find(|e| e["action"] == "action.uploaded")
        .unwrap_or_else(|| panic!("no action.uploaded row: {audit}"));

    // Both halves, because a divergence between them is the entire signal and
    // this row is the only place it survives.
    assert_eq!(row["detail"]["declared_sha256"], UPLOAD_SHA);
    assert_eq!(row["detail"]["measured_sha256"], UPLOAD_SHA);
    assert_eq!(row["detail"]["measured_size_bytes"], UPLOAD_BODY.len());
    assert_eq!(row["detail"]["is_error"], false);
    assert_eq!(
        row["detail"]["stored_media_path"],
        format!("/media/{UPLOAD_SHA}")
    );
    // The body streams through and is never buffered, so it cannot be captured.
    assert_eq!(row["detail"]["request"]["skipped"], "streamed");
}

// ── The media ledger ────────────────────────────────────────────────────

#[tokio::test]
async fn an_uploaded_reference_is_described_in_a_later_approval() {
    let pool = common::test_pool().await;
    let fx = setup_for_disclosure(pool).await;

    let d = mint(
        &fx,
        json!({ "filename": "invoice.pdf", "mime": "application/pdf" }),
    )
    .await;
    let push = fx
        .client
        .post(d["upload_url"].as_str().unwrap())
        .header("content-type", "application/pdf")
        .body(UPLOAD_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(push.status(), 201);
    let stored: Value = push.json().await.unwrap();
    let media_path = stored["media_path"].as_str().unwrap().to_string();

    // Send it. The approval's primary row is what a reviewer actually reads,
    // and a bare content hash tells them nothing about what they are
    // approving.
    let disclosed = disclosed_file_row(&fx, &media_path).await;
    assert_eq!(
        disclosed,
        format!("invoice.pdf (application/pdf, {} bytes)", UPLOAD_BODY.len()),
        "the File row should describe the bytes, not hash them"
    );
}

#[tokio::test]
async fn a_downloaded_reference_is_described_even_without_deliver_url() {
    let pool = common::test_pool().await;
    let fx = setup_for_disclosure(pool).await;

    // The common forwarding path: `download_media` *without* `deliver: "url"`
    // returns the raw reference so it can be re-sent. Recording only on the
    // deferred path would leave exactly this case unenriched — which is most
    // of them.
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .json(&json!({
            "service": "upstub", "action": "download_media",
            "params": { "chat_jid": "34600@s.whatsapp.net" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let disclosed = disclosed_file_row(&fx, &format!("/media/{UPLOAD_SHA}")).await;
    assert_eq!(disclosed, "report.pdf (application/pdf, 12345 bytes)");
}

#[tokio::test]
async fn a_reference_the_gateway_never_saw_falls_back_to_the_raw_path() {
    let pool = common::test_pool().await;
    let fx = setup_for_disclosure(pool).await;

    // Bytes pushed to the container out of band were never seen here. The
    // fallback is lossless — the reviewer still sees exactly the string the
    // call will send — so a miss is less helpful, never misleading.
    let unseen = "/media/deadbeef";
    let disclosed = disclosed_file_row(&fx, unseen).await;
    assert_eq!(disclosed, unseen);
}

/// Call `send_file` and read back the approval's primary "File" row.
///
/// Goes through a real gated call rather than poking the resolver directly:
/// the whole claim under test is that the enrichment reaches the surface a
/// human reads.
async fn disclosed_file_row(fx: &Fx, media_path: &str) -> String {
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth(&fx.agent_key).0, auth(&fx.agent_key).1)
        .json(&json!({
            "service": "upstub", "action": "send_file",
            "params": { "recipient": "34600@s.whatsapp.net", "media_path": media_path },
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    body["disclosed_fields"]
        .as_array()
        .unwrap_or_else(|| panic!("no disclosed_fields: {body}"))
        .iter()
        .find(|f| f["label"] == "File")
        .and_then(|f| f["value"].as_str())
        .unwrap_or_else(|| panic!("no File row: {body}"))
        .to_string()
}
