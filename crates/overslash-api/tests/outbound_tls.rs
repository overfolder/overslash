//! TLS on outbound service requests (CASA 4.1.1), end to end.
//!
//! Every action request can carry a vault credential, so the gateway refuses
//! plain `http` — at the boundary where an endpoint is written, when a call is
//! resolved, and on every hop the transport dials. The one way past it is the
//! operator allow-list the SSRF guard already reads
//! (`OVERSLASH_SSRF_ALLOWED_CIDRS`); the suite sets it to loopback, which is
//! how the `http://127.0.0.1` fakes stay reachable, and which these tests also
//! assert as the escape hatch.
//!
//! The refused target is `93.184.216.34`: a public address, so the SSRF guard
//! would let it through and only the TLS rule stands in the way — and an IP
//! literal, so nothing here depends on DNS or ever reaches the network.
//!
//! Bare `sqlx::query` in one test: it simulates an endpoint stored before
//! https was required, which no API path can write any more.
#![allow(clippy::disallowed_methods)]

use crate::common;

use axum::response::{IntoResponse, Redirect};
use serde_json::{Value, json};

use common::auth;

/// Public, so the SSRF guard has no objection — only TLS refuses it.
const PLAINTEXT_PUBLIC: &str = "http://93.184.216.34";

async fn boot() -> (String, reqwest::Client, String, sqlx::PgPool) {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    common::allow_loopback_ssrf();
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org, _ident, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    (base, client, admin_key, pool)
}

async fn post(client: &reqwest::Client, url: String, key: &str, body: Value) -> (u16, String) {
    let resp = client
        .post(url)
        .header(auth(key).0, auth(key).1)
        .json(&body)
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

async fn call(client: &reqwest::Client, base: &str, key: &str, body: Value) -> (u16, String) {
    post(client, format!("{base}/v1/actions/call"), key, body).await
}

fn is_tls_refusal(body: &str) -> bool {
    body.contains("refusing plain http://")
}

// ── Mode A ──────────────────────────────────────────────────────────

#[tokio::test]
async fn mode_a_refuses_plain_http_carrying_a_vault_secret() {
    let (base, client, key, _pool) = boot().await;
    let put = client
        .put(format!("{base}/v1/secrets/upstream_token"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({ "value": "tls-test-secret-value" }))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "secret put: {}", put.status());

    let (status, body) = call(
        &client,
        &base,
        &key,
        json!({
            "service": "http",
            "method": "GET",
            "url": format!("{PLAINTEXT_PUBLIC}/api"),
            "secrets": [{ "name": "upstream_token", "inject_as": "header", "header_name": "X-Auth" }],
        }),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(is_tls_refusal(&body), "expected the TLS refusal: {body}");
    assert!(!body.contains("tls-test-secret-value"), "leaked: {body}");
}

/// Uncredentialed Mode A is refused too — one rule, not a second one that has
/// to decide which calls are "uncredentialed".
#[tokio::test]
async fn mode_a_refuses_plain_http_without_credentials() {
    let (base, client, key, _pool) = boot().await;
    let (status, body) = call(
        &client,
        &base,
        &key,
        json!({ "service": "http", "method": "GET", "url": format!("{PLAINTEXT_PUBLIC}/") }),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(is_tls_refusal(&body), "{body}");
}

/// https clears the TLS rule. Nothing listens on port 1, so the call fails
/// later — at connect — and never with the TLS refusal.
#[tokio::test]
async fn mode_a_https_is_not_refused_for_tls() {
    let (base, client, key, _pool) = boot().await;
    let (status, body) = call(
        &client,
        &base,
        &key,
        json!({ "service": "http", "method": "GET", "url": "https://127.0.0.1:1/" }),
    )
    .await;
    assert!(
        !is_tls_refusal(&body),
        "https must pass the TLS rule: {body}"
    );
    assert_ne!(status, 200);
}

/// The escape hatch: a plain-http target inside the operator allow-list
/// (loopback, in this suite) is still reached.
#[tokio::test]
async fn mode_a_plain_http_to_an_operator_allowed_range_still_works() {
    let (base, client, key, _pool) = boot().await;
    let mock = common::start_mock().await;
    let (status, body) = call(
        &client,
        &base,
        &key,
        json!({ "service": "http", "method": "GET", "url": format!("http://{mock}/echo") }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

/// The transport re-checks every hop, so an allowed first hop cannot redirect
/// the request down to plaintext on a public host.
#[tokio::test]
async fn a_redirect_to_plain_http_is_refused_at_the_next_hop() {
    let (base, client, key, _pool) = boot().await;
    let app = axum::Router::new().route(
        "/bounce",
        axum::routing::get(|| async {
            Redirect::temporary(&format!("{PLAINTEXT_PUBLIC}/landing")).into_response()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirector = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (status, body) = call(
        &client,
        &base,
        &key,
        json!({ "service": "http", "method": "GET", "url": format!("http://{redirector}/bounce") }),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(is_tls_refusal(&body), "{body}");
}

// ── Mode C: instance endpoints ──────────────────────────────────────

async fn create_langfuse(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    name: &str,
    url: &str,
) -> (u16, String) {
    let everyone = common::everyone_group_id(base, client, key).await;
    post(
        client,
        format!("{base}/v1/services"),
        key,
        json!({
            "template_key": "langfuse",
            "name": name,
            "url": url,
            "user_level": false,
            "groups": [{ "group_id": everyone.to_string(), "access_level": "write", "auto_approve_reads": true }],
            "status": "active",
            "credentials": { "secret_key": "langfuse_secret_key" },
            "config": { "public_key": "pk-lf-test" },
        }),
    )
    .await
}

async fn put_langfuse_secret(client: &reqwest::Client, base: &str, key: &str) {
    let put = client
        .put(format!("{base}/v1/secrets/langfuse_secret_key"))
        .header(auth(key).0, auth(key).1)
        .json(&json!({ "value": "sk-lf-test" }))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "secret put: {}", put.status());
}

#[tokio::test]
async fn an_instance_url_over_plain_http_is_refused_at_create_and_update() {
    let (base, client, key, _pool) = boot().await;
    put_langfuse_secret(&client, &base, &key).await;

    let (status, body) = create_langfuse(&client, &base, &key, "lf_plain", PLAINTEXT_PUBLIC).await;
    assert_eq!(status, 400, "{body}");
    assert!(is_tls_refusal(&body), "{body}");
    assert!(
        body.contains("`url`"),
        "the error must name the field: {body}"
    );

    // Created against the loopback fake (the escape hatch), then pointed at a
    // public plaintext endpoint: the update is refused the same way.
    let mock = common::start_mock().await;
    let (status, body) =
        create_langfuse(&client, &base, &key, "lf_local", &format!("http://{mock}")).await;
    assert_eq!(status, 200, "loopback is operator-allowed here: {body}");
    let id = serde_json::from_str::<Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({ "url": PLAINTEXT_PUBLIC }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 400, "{body}");
    assert!(is_tls_refusal(&body), "{body}");

    let resp = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({ "url": "https://langfuse.example.com" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "https must be accepted: {body}");
}

/// An endpoint stored before https was required is used verbatim with the
/// injected credential — the production gap. It must now fail at resolve,
/// before any approval exists, with the fix in the message.
#[tokio::test]
async fn a_stored_plain_http_instance_url_is_refused_at_call_time() {
    let (base, client, key, pool) = boot().await;
    put_langfuse_secret(&client, &base, &key).await;
    let mock = common::start_mock().await;
    let (status, body) =
        create_langfuse(&client, &base, &key, "langfuse", &format!("http://{mock}")).await;
    assert_eq!(status, 200, "{body}");
    let id: uuid::Uuid = serde_json::from_str::<Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    sqlx::query("UPDATE service_instances SET url = $2 WHERE id = $1")
        .bind(id)
        .bind(PLAINTEXT_PUBLIC)
        .execute(&pool)
        .await
        .unwrap();

    let (status, body) = call(
        &client,
        &base,
        &key,
        json!({ "service": "langfuse", "action": "list_prompts", "params": {} }),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(is_tls_refusal(&body), "{body}");
    assert!(!body.contains("sk-lf-test"), "leaked: {body}");
}

// ── Templates and layers ────────────────────────────────────────────

fn mcp_template(key: &str, url: &str) -> String {
    format!(
        r#"openapi: 3.1.0
info:
  title: {key}
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth: {{ kind: bearer }}
  autodiscover: false
  tools:
    - name: echo
      risk: read
      description: Echo
      input_schema:
        type: object
        properties: {{ x: {{ type: string }} }}
"#
    )
}

fn issue_codes(body: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let errors = v["report"]["errors"]
        .as_array()
        .or_else(|| v["errors"].as_array())
        .cloned()
        .unwrap_or_default();
    errors
        .iter()
        .filter_map(|e| e["code"].as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn a_custom_template_mcp_url_over_plain_http_is_refused() {
    let (base, client, key, _pool) = boot().await;

    let (status, body) = post(
        &client,
        format!("{base}/v1/templates"),
        &key,
        json!({ "openapi": mcp_template("plainmcp", &format!("{PLAINTEXT_PUBLIC}/mcp")) }),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        issue_codes(&body).contains(&"endpoint_requires_https".to_string()),
        "{body}"
    );

    // The editor's live lint says the same thing before anything is saved.
    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&key).0, auth(&key).1)
        .body(mcp_template("plainmcp", &format!("{PLAINTEXT_PUBLIC}/mcp")))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        issue_codes(&body).contains(&"endpoint_requires_https".to_string()),
        "{body}"
    );

    let (status, body) = post(
        &client,
        format!("{base}/v1/templates"),
        &key,
        json!({ "openapi": mcp_template("tlsmcp", "https://mcp.example.com/mcp") }),
    )
    .await;
    assert_eq!(status, 200, "https must be accepted: {body}");
}

#[tokio::test]
async fn an_org_layer_default_url_over_plain_http_is_refused() {
    let (base, client, key, _pool) = boot().await;
    let (status, body) = post(
        &client,
        format!("{base}/v1/templates"),
        &key,
        json!({ "openapi": common::minimal_openapi("tlsbase") }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let delta = json!({ "instance_defaults": { "url": format!("{PLAINTEXT_PUBLIC}/api") } });
    let (status, body) = post(
        &client,
        format!("{base}/v1/templates"),
        &key,
        json!({ "extends": "tlsbase", "key": "tlsbase_org", "delta": delta }),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        issue_codes(&body).contains(&"endpoint_requires_https".to_string()),
        "{body}"
    );

    let (_, body) = post(
        &client,
        format!("{base}/v1/templates/validate-delta"),
        &key,
        json!({ "extends": "tlsbase", "delta": delta }),
    )
    .await;
    assert!(
        issue_codes(&body).contains(&"endpoint_requires_https".to_string()),
        "the layer editor's live lint must flag it too: {body}"
    );

    let (status, body) = post(
        &client,
        format!("{base}/v1/templates"),
        &key,
        json!({
            "extends": "tlsbase",
            "key": "tlsbase_org",
            "delta": { "instance_defaults": { "url": "https://gw.acme.example" } },
        }),
    )
    .await;
    assert_eq!(status, 200, "https must be accepted: {body}");
}
