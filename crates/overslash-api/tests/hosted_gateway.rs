//! Platform-hosted MCP gateways (docs/design/hosted-runtimes.md, Phase 0),
//! end to end against the shipped `services/whatsapp.yaml`.
//!
//! The deployment sets `WHATSAPP_MCP_URL` and the platform credential
//! `whatsapp_gateway_key`, pinned to that host. A stub stands in for the
//! shared multi-tenant gateway and records the two headers each request
//! carries:
//!
//!   • `Authorization: Bearer <session token>`: per instance, minted by
//!     Overslash when the instance keeps the template's own URL.
//!   • `X-Gateway-Key: <key>`: the deployment's outer key, from the org vault
//!     if the org stored one, else from the platform, and only ever on the
//!     platform host.

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const HOST: &str = "whatsapp-mcp.hosted.test";
const PLATFORM_KEY: &str = "platform-whatsapp-key";
const MEDIA_SHA: &str = "aa11";

#[derive(Clone, Debug, Default)]
struct Seen {
    authorization: Option<String>,
    gateway_key: Option<String>,
}

type Sink = Arc<Mutex<Vec<Seen>>>;

fn record(sink: &Sink, headers: &HeaderMap) {
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    sink.lock().unwrap().push(Seen {
        authorization: h("authorization"),
        gateway_key: h("x-gateway-key"),
    });
}

async fn mcp(State(sink): State<Sink>, headers: HeaderMap, Json(req): Json<Value>) -> Json<Value> {
    record(&sink, &headers);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let tool = req
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let result = match (method, tool) {
        ("initialize", _) => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub-hosted-whatsapp", "version": "0" },
            "capabilities": {}
        }),
        ("tools/call", "download_media") => json!({
            "content": [{ "type": "text", "text": "media" }],
            "structuredContent": {
                "media_path": format!("/media/{MEDIA_SHA}"),
                "mime": "image/png",
                "size": 3,
                "filename": "a.png",
                "sha256": MEDIA_SHA,
            },
            "isError": false
        }),
        ("tools/call", _) => json!({
            "content": [{ "type": "text", "text": "[]" }],
            "structuredContent": { "chats": [] },
            "isError": false
        }),
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn media(State(sink): State<Sink>, headers: HeaderMap) -> &'static [u8] {
    record(&sink, &headers);
    b"png"
}

async fn start_stub() -> (SocketAddr, Sink) {
    common::allow_loopback_ssrf();
    let sink: Sink = Arc::default();
    let app = Router::new()
        .route("/mcp", post(mcp))
        .route("/media/{sha}", get(media))
        .with_state(sink.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, sink)
}

struct Api {
    base: String,
    client: Client,
    agent_key: String,
    admin_key: String,
}

/// Boot the API as a deployment that hosts the WhatsApp gateway at `HOST`,
/// routed to the stub.
async fn start_hosting(stub: SocketAddr) -> Api {
    let pool = common::test_pool().await;
    let vars = overslash_core::template_vars::Vars::from_pairs([(
        "WHATSAPP_MCP_URL",
        format!("https://{HOST}/mcp").as_str(),
    )]);
    let (base, client) = common::start_api_with_registry_vars(pool, None, vars, move |cfg| {
        cfg.platform_credentials = vec![overslash_api::config::PlatformCredential {
            secret_name: "whatsapp_gateway_key".into(),
            host: HOST.into(),
            value: PLATFORM_KEY.into(),
        }];
        cfg.service_base_overrides
            .insert(HOST.into(), format!("http://{stub}"));
    })
    .await;
    let (_org, agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": agent_ident,
            "action_pattern": "whatsapp:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "permission: {}", resp.status());
    Api {
        base,
        client,
        agent_key,
        admin_key,
    }
}

impl Api {
    async fn create(&self, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}/v1/services", self.base))
            .header("Authorization", format!("Bearer {}", self.agent_key))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn call(
        &self,
        service: &str,
        action: &str,
        params: Value,
        deliver: Option<&str>,
    ) -> Value {
        let mut body = json!({ "service": service, "action": action, "params": params });
        if let Some(d) = deliver {
            body["deliver"] = json!(d);
        }
        let resp = self
            .client
            .post(format!("{}/v1/actions/call", self.base))
            .header("Authorization", format!("Bearer {}", self.agent_key))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let body: Value = resp.json().await.unwrap();
        assert_eq!(status, 200, "call {action}: {body}");
        body
    }
}

fn bearer_of(seen: &Seen) -> &str {
    seen.authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .expect("bearer present")
}

#[tokio::test]
async fn hosted_instance_gets_a_minted_token_and_the_platform_key() {
    let (stub, sink) = start_stub().await;
    let api = start_hosting(stub).await;

    // No url, no secret: the user just picks WhatsApp.
    let resp = api
        .create(json!({ "name": "whatsapp", "template_key": "whatsapp" }))
        .await;
    assert_eq!(resp.status(), 200, "create: {:?}", resp.text().await);
    let inst: Value = resp.json().await.unwrap();
    let bound = inst["secret_name"].as_str().expect("token bound");
    // Shown by its bare name: it lives in the owner's own vault.
    assert!(
        bound.starts_with("whatsapp_session_"),
        "the minted token is bound as the instance's secret, got {bound}"
    );

    api.call("whatsapp", "list_chats", json!({}), None).await;

    let seen = sink.lock().unwrap().clone();
    let last = seen.last().expect("gateway saw the call");
    let token = bearer_of(last);
    assert_eq!(token.len(), 43, "32 random bytes, base64url: {token}");
    assert_ne!(token, PLATFORM_KEY);
    assert_eq!(
        last.gateway_key.as_deref(),
        Some(PLATFORM_KEY),
        "no org key stored: the platform supplies the gateway key"
    );

    // A second instance is a second tenant: a different token.
    let resp = api
        .create(json!({ "name": "whatsapp_work", "template_key": "whatsapp" }))
        .await;
    assert_eq!(resp.status(), 200, "second create: {:?}", resp.text().await);
    api.call("whatsapp_work", "list_chats", json!({}), None)
        .await;
    let seen = sink.lock().unwrap().clone();
    assert_ne!(bearer_of(seen.last().unwrap()), token);
}

#[tokio::test]
async fn an_org_stored_gateway_key_beats_the_platform_one() {
    let (stub, sink) = start_stub().await;
    let api = start_hosting(stub).await;

    let resp = api
        .client
        .put(format!(
            "{}/v1/secrets/whatsapp_gateway_key?scope=org",
            api.base
        ))
        .header("Authorization", format!("Bearer {}", api.admin_key))
        .json(&json!({ "value": "org-own-key" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "org secret: {}", resp.status());

    let resp = api
        .create(json!({ "name": "whatsapp", "template_key": "whatsapp" }))
        .await;
    assert_eq!(resp.status(), 200, "create: {:?}", resp.text().await);
    api.call("whatsapp", "list_chats", json!({}), None).await;

    let seen = sink.lock().unwrap().clone();
    assert_eq!(
        seen.last().unwrap().gateway_key.as_deref(),
        Some("org-own-key")
    );
}

/// An instance on the user's own server is single-tenant and self-hosted: it
/// must bring that server's token (nothing is minted), and neither the
/// platform key nor the org's gateway key may reach it.
#[tokio::test]
async fn own_server_brings_its_token_and_never_receives_a_gateway_key() {
    let (stub, sink) = start_stub().await;
    let api = start_hosting(stub).await;
    let own_url = format!("http://{stub}/mcp");

    let resp = api
        .create(json!({ "name": "whatsapp", "template_key": "whatsapp", "url": own_url }))
        .await;
    assert_eq!(
        resp.status(),
        400,
        "an own server's token cannot be invented: {:?}",
        resp.text().await
    );

    let resp = api
        .client
        .put(format!("{}/v1/secrets/my_container_token", api.base))
        .header("Authorization", format!("Bearer {}", api.agent_key))
        .json(&json!({ "value": "container-token" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = api
        .create(json!({
            "name": "whatsapp",
            "template_key": "whatsapp",
            "url": own_url,
            "secret_name": "my_container_token",
        }))
        .await;
    assert_eq!(resp.status(), 200, "create: {:?}", resp.text().await);
    api.call("whatsapp", "list_chats", json!({}), None).await;

    let seen = sink.lock().unwrap().clone();
    let last = seen.last().unwrap();
    assert_eq!(
        last.authorization.as_deref(),
        Some("Bearer container-token")
    );
    assert_eq!(
        last.gateway_key, None,
        "the platform key is pinned to the platform host"
    );
}

/// `download_media` hands back a capability URL whose fetch re-presents the
/// instance's credentials. On a hosted instance that is both keys.
#[tokio::test]
async fn media_fetch_re_presents_both_keys() {
    let (stub, sink) = start_stub().await;
    let api = start_hosting(stub).await;
    let resp = api
        .create(json!({ "name": "whatsapp", "template_key": "whatsapp" }))
        .await;
    assert_eq!(resp.status(), 200, "create: {:?}", resp.text().await);

    let body = api
        .call(
            "whatsapp",
            "download_media",
            json!({ "chat_jid": "34600@s.whatsapp.net", "message_id": "M1" }),
            Some("url"),
        )
        .await;
    let result: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let url = result["download_url"].as_str().expect("download_url");
    let token = bearer_of(sink.lock().unwrap().last().unwrap()).to_string();

    let file = api.client.get(url).send().await.unwrap();
    assert_eq!(file.status(), 200);
    assert_eq!(file.bytes().await.unwrap().as_ref(), b"png");

    let seen = sink.lock().unwrap().clone();
    let fetch = seen.last().unwrap();
    assert_eq!(
        fetch.authorization.as_deref(),
        Some(&*format!("Bearer {token}"))
    );
    assert_eq!(fetch.gateway_key.as_deref(), Some(PLATFORM_KEY));
}

#[tokio::test]
async fn template_detail_says_the_token_is_minted() {
    let (stub, _sink) = start_stub().await;
    let api = start_hosting(stub).await;
    let detail: Value = api
        .client
        .get(format!("{}/v1/templates/whatsapp", api.base))
        .header("Authorization", format!("Bearer {}", api.agent_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["mcp"]["generates_session_token"], true, "{detail}");
    assert_eq!(detail["mcp"]["url"], format!("https://{HOST}/mcp"));
}

/// A deployment that hosts nothing: the template is the old
/// bring-your-own-server one, byte for byte in behaviour.
#[tokio::test]
async fn without_the_deployment_variable_the_template_is_self_hosted() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        overslash_core::template_vars::Vars::default(),
        |_| {},
    )
    .await;
    let (_org, _ident, agent_key, _admin) = common::bootstrap_org_identity(&base, &client).await;

    let detail: Value = client
        .get(format!("{base}/v1/templates/whatsapp"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(detail["mcp"]["url"].is_null(), "{detail}");
    assert!(detail["mcp"].get("generates_session_token").is_none());

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({ "name": "whatsapp", "template_key": "whatsapp" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "needs a url: {:?}", resp.text().await);
}
