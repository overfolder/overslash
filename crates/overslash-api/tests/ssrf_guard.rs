//! The SSRF guard, end-to-end on the two paths that carry a caller-supplied
//! URL all the way to a socket: Mode A raw HTTP (`POST /v1/actions/call`) and
//! webhook delivery.
//!
//! # Why these tests can run at all
//!
//! The whole suite runs with `OVERSLASH_SSRF_ALLOWED_CIDRS=127.0.0.0/8,::1/128`,
//! because the Mode A and Mode C fakes are bound to loopback. That is the same
//! operator allow-list a self-hosted deployment uses for its own private
//! network — there is no test-only bypass — and it opens **those ranges and
//! nothing else**, which is what makes this file possible: the fakes stay
//! reachable while the link-local, RFC1918 and CGNAT addresses an attacker
//! actually wants stay refused. If someone ever widens that list, every test
//! here goes green for the wrong reason, and the two positive controls are what
//! would still catch the opposite mistake.

use crate::common;

use axum::response::{IntoResponse, Redirect};
use serde_json::{Value, json};

/// The AWS/GCP/Azure instance-metadata address — the canonical SSRF target,
/// and the one CASA 5.1.5 is written about.
const METADATA: &str = "http://169.254.169.254/latest/meta-data/";

/// The same target over `https`, for the Mode A tests. A Mode A call to a
/// plain-`http` address outside the operator allow-list is now refused for
/// want of TLS (CASA 4.1.1, `tests/outbound_tls.rs`) before the SSRF guard is
/// ever consulted — so a test that means to prove the *guard* refuses an
/// address has to ask for it over https, or it passes for the wrong reason.
const METADATA_TLS: &str = "https://169.254.169.254/latest/meta-data/";

async fn boot(pool: sqlx::PgPool) -> (String, String, uuid::Uuid, std::net::SocketAddr) {
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let mock = common::start_mock().await;
    let (org_id, _ident, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    (base, admin_key, org_id, mock)
}

/// A Mode A raw-HTTP call. The admin identity is a *user*, which Layer 2 gates
/// by group only, so these execute straight through instead of filing an
/// approval — which is exactly what puts the transport under test.
async fn raw_http(base: &str, key: &str, url: &str) -> reqwest::Response {
    raw_http_body(
        base,
        key,
        json!({ "service": "http", "method": "GET", "url": url }),
    )
    .await
}

async fn raw_http_body(base: &str, key: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

// ── Mode A: the addresses that must never be dialed ─────────────────

#[tokio::test]
async fn mode_a_refuses_the_cloud_metadata_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let resp = raw_http(&base, &key, METADATA_TLS).await;
    assert_eq!(
        resp.status(),
        400,
        "the metadata endpoint must be refused, not proxied"
    );
    let body: Value = resp.json().await.unwrap();
    let msg = body.to_string();
    assert!(
        msg.contains("169.254.169.254") && msg.contains("refusing to connect"),
        "expected an SSRF refusal, got {msg}"
    );
    // The point of the finding: the response must not be the metadata body.
    assert!(!msg.contains("ami-id"), "leaked an upstream body: {msg}");
}

#[tokio::test]
async fn mode_a_refuses_private_and_cgnat_addresses() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    // https, so it is the guard doing the refusing — see `METADATA_TLS`.
    for url in [
        "https://10.0.0.1/admin",
        "https://192.168.1.1/",
        "https://172.16.0.1/",
        // Carrier-grade NAT — the range a cloud load balancer's internal
        // plane lives on.
        "https://100.64.0.1/",
        // IPv6 unique-local and the v4-mapped spelling of RFC1918.
        "https://[fd00::1]/",
        "https://[::ffff:10.0.0.1]/",
    ] {
        let resp = raw_http(&base, &key, url).await;
        assert_eq!(resp.status(), 400, "{url} should have been refused");
        let msg = resp.text().await.unwrap();
        assert!(
            msg.contains("refusing to connect"),
            "{url}: expected the SSRF guard's refusal, got {msg}"
        );
    }
}

#[tokio::test]
async fn mode_a_refuses_a_non_http_scheme() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let resp = raw_http(&base, &key, "file:///etc/passwd").await;
    assert_eq!(resp.status(), 400);
}

/// The streamed fork has its own transport call. It must refuse the same
/// addresses — a guard that only covers the buffered path is not a guard.
#[tokio::test]
async fn mode_a_refuses_the_metadata_endpoint_when_streaming() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let resp = raw_http_body(
        &base,
        &key,
        json!({
            "service": "http",
            "method": "GET",
            "url": METADATA_TLS,
            "prefer_stream": true,
        }),
    )
    .await;
    assert_eq!(resp.status(), 400, "the streamed fork must refuse too");
}

// ── Mode A: the positive controls ───────────────────────────────────

/// Without this the file could pass with the transport simply broken.
#[tokio::test]
async fn mode_a_still_reaches_a_loopback_fake() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool).await;

    let resp = raw_http(&base, &key, &format!("http://{mock}/echo?ok=1")).await;
    assert_eq!(resp.status(), 200, "the loopback hatch must still work");
}

/// A redirect is the other half of the finding: a check made at the URL layer
/// is defeated by a cooperative server answering 302. Following is not
/// optional — a Drive download *is* a redirect to a signed URL — so the
/// transport follows by hand and re-runs the guard on every hop. The metadata
/// endpoint is therefore refused at hop two, exactly as it is at hop one.
#[tokio::test]
async fn a_redirect_toward_the_metadata_endpoint_is_refused_at_the_next_hop() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let redirector = start_redirector(METADATA.to_string()).await;

    let resp = raw_http(&base, &key, &format!("http://{redirector}/bounce")).await;
    assert_eq!(resp.status(), 400, "hop two must be checked like hop one");

    let body: Value = resp.json().await.unwrap();
    let msg = body.to_string();
    assert!(
        msg.contains("169.254.169.254") && msg.contains("refusing to connect"),
        "expected the guard to refuse the redirect target, got {msg}"
    );
    assert!(!msg.contains("ami-id"), "followed the redirect: {msg}");
}

/// An injected credential must not ride a redirect to another host. On this
/// path `Authorization` is a vault secret, so forwarding it to wherever an
/// upstream points would disclose it — to a CDN in the benign case, and to
/// whoever the upstream names in the other one.
#[tokio::test]
async fn a_cross_host_redirect_drops_the_injected_credential() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    // `[::1]` and `127.0.0.1` are the same machine and different hosts, which
    // is exactly the distinction under test — and both are loopback, so the
    // suite's hatch reaches them.
    let sink = start_header_sink().await;
    let redirector = start_redirector(format!("http://[::1]:{}/sink", sink.port())).await;

    let resp = raw_http_body(
        &base,
        &key,
        json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{redirector}/bounce"),
            "headers": { "Authorization": "Bearer super-secret-upstream-token" },
        }),
    )
    .await;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status, 200,
        "the second hop should have been reached: {body}"
    );

    // The sink echoes the request headers it actually received, so this is an
    // assertion about what crossed the wire on hop two, not about our intent.
    let echoed = body["result"]["body"].as_str().unwrap_or_default();
    assert!(
        echoed.contains("\"reached\":true"),
        "the sink was not reached: {body}"
    );
    assert!(
        !echoed.contains("super-secret-upstream-token"),
        "the credential crossed a host boundary: {echoed}"
    );
}

/// A loopback server on the IPv6 side that reports the headers it was sent.
async fn start_header_sink() -> std::net::SocketAddr {
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            let seen: Vec<String> = headers
                .iter()
                .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("")))
                .collect();
            axum::Json(json!({ "reached": true, "headers": seen }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// A loopback server whose only job is to point somewhere else.
async fn start_redirector(to: String) -> std::net::SocketAddr {
    let app = axum::Router::new().route(
        "/bounce",
        axum::routing::get(move || {
            let to = to.clone();
            async move { Redirect::temporary(&to).into_response() }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

// ── Webhook delivery ────────────────────────────────────────────────

async fn create_subscription(base: &str, key: &str, url: &str, event: &str) -> uuid::Uuid {
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({ "url": url, "events": [event] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "webhook creation failed");
    let body: Value = resp.json().await.unwrap();
    body["id"].as_str().unwrap().parse().unwrap()
}

/// `(status_code, response_body)` of the single delivery recorded for a
/// subscription.
async fn only_delivery(pool: &sqlx::PgPool, sub: uuid::Uuid) -> (Option<i32>, Option<String>) {
    let rows = sqlx::query!(
        "SELECT status_code, response_body FROM webhook_deliveries WHERE subscription_id = $1",
        sub
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "expected exactly one delivery attempt");
    (rows[0].status_code, rows[0].response_body.clone())
}

/// The registrant-supplied URL is the SSRF vector, and the delivery row
/// records the response *body* — so an unguarded dispatcher is a read oracle,
/// not just a blind request. Both outbound requests are guarded: the
/// ownership handshake at registration (CASA 7.1.2) and every delivery.
#[tokio::test]
async fn webhook_delivery_refuses_a_link_local_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org_id, _mock) = boot(pool.clone()).await;

    // `https`, because a plain-`http` webhook is refused at registration now
    // (CASA 7.1.1) — and the guard must refuse the address regardless.
    let metadata_https = METADATA.replacen("http://", "https://", 1);
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({ "url": metadata_https, "events": ["ssrf.probe"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "webhook creation failed");
    let body: Value = resp.json().await.unwrap();
    let sub: uuid::Uuid = body["id"].as_str().unwrap().parse().unwrap();

    // The handshake went through the guard and was refused before dialing.
    assert_eq!(body["verification_status"], "pending_verification");
    let why = body["verification_error"].as_str().unwrap_or_default();
    assert!(
        why.contains("refusing to connect") && why.contains("169.254.169.254"),
        "expected the guard's refusal as the verification error, got {why:?}"
    );

    // Deliveries are guarded on their own, not just by the handshake having
    // failed: force the row verified and dispatch.
    sqlx::query!(
        "UPDATE webhook_subscriptions SET verification_status = 'verified' WHERE id = $1",
        sub
    )
    .execute(&pool)
    .await
    .unwrap();
    overslash_api::services::webhook_dispatcher::dispatch(
        &pool,
        org_id,
        "ssrf.probe",
        json!({ "probe": true }),
    )
    .await;

    let (status, body) = only_delivery(&pool, sub).await;
    assert_eq!(status, None, "nothing answered, so there is no status");
    let body = body.unwrap_or_default();
    assert!(
        body.contains("refusing to connect") && body.contains("169.254.169.254"),
        "expected the guard's refusal on the delivery row, got {body:?}"
    );
}

#[tokio::test]
async fn webhook_delivery_still_reaches_a_loopback_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org_id, mock) = boot(pool.clone()).await;

    let sub = create_subscription(
        &base,
        &key,
        &format!("http://{mock}/webhooks/receive"),
        "ssrf.probe",
    )
    .await;

    overslash_api::services::webhook_dispatcher::dispatch(
        &pool,
        org_id,
        "ssrf.probe",
        json!({ "probe": true }),
    )
    .await;

    let (status, _body) = only_delivery(&pool, sub).await;
    assert_eq!(
        status,
        Some(200),
        "the loopback endpoint must still deliver"
    );
}

// ── OIDC issuer discovery ───────────────────────────────────────────
//
// An org admin supplies `issuer_url`, and both `POST /v1/org-idp-configs` and
// the `/discover` preview fetch its discovery document. Same guard, per hop,
// plus a scheme rule of its own: `https`, or plain `http` to loopback only.
// And unlike Mode A, the caller never sees what the network said — so the
// assertions here are as much about what the error *omits* as that it fails.

/// The two endpoints that fetch an issuer, each hit with `issuer_url`.
async fn discover_both(base: &str, key: &str, issuer_url: &str) -> Vec<(u16, String)> {
    let client = reqwest::Client::new();
    let preview = client
        .post(format!("{base}/v1/org-idp-configs/discover"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({ "issuer_url": issuer_url }))
        .send()
        .await
        .unwrap();
    let create = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "issuer_url": issuer_url,
            "client_id": "cid",
            "client_secret": "csecret",
        }))
        .send()
        .await
        .unwrap();
    let mut out = Vec::new();
    for resp in [preview, create] {
        let status = resp.status().as_u16();
        out.push((status, resp.text().await.unwrap()));
    }
    out
}

/// Both endpoints fail with the generic discovery error, and neither names
/// anything in `must_not_leak`.
async fn assert_generic_refusal(base: &str, key: &str, issuer_url: &str, must_not_leak: &[&str]) {
    for (status, body) in discover_both(base, key, issuer_url).await {
        assert_eq!(status, 400, "{issuer_url}: expected a refusal, got {body}");
        assert!(
            body.contains("OIDC discovery failed")
                && body.contains("could not retrieve a valid discovery document"),
            "{issuer_url}: expected the generic discovery error, got {body}"
        );
        for leak in must_not_leak
            .iter()
            .chain(&["refusing to connect", "ami-id"])
        {
            assert!(
                !body.contains(leak),
                "{issuer_url}: the error leaked {leak:?}: {body}"
            );
        }
    }
}

/// A loopback "issuer" that answers every path with `respond()`.
async fn start_issuer<F>(respond: F) -> std::net::SocketAddr
where
    F: Fn() -> axum::response::Response + Clone + Send + Sync + 'static,
{
    let app = axum::Router::new().fallback(move || {
        let respond = respond.clone();
        async move { respond() }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// An issuer that redirects its discovery document to `to`.
async fn start_redirecting_issuer(to: &'static str) -> std::net::SocketAddr {
    start_issuer(move || Redirect::temporary(to).into_response()).await
}

/// The finding in its plainest form: a private address is refused before a
/// socket is opened, and the caller is not told why.
#[tokio::test]
async fn oidc_discovery_refuses_a_private_ip_issuer() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    assert_generic_refusal(&base, &key, "https://10.0.0.1", &["10.0.0.1"]).await;
    assert_generic_refusal(&base, &key, "https://169.254.169.254", &["169.254"]).await;
}

/// The shared client used to follow redirects without looking. Hop one here
/// is a legitimate (loopback, allow-listed) issuer; hop two is where it
/// points inward, and it must be checked exactly like hop one.
#[tokio::test]
async fn oidc_discovery_refuses_a_redirect_to_a_private_address() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let to_metadata = start_redirecting_issuer(METADATA).await;
    assert_generic_refusal(&base, &key, &format!("http://{to_metadata}"), &["169.254"]).await;

    let to_rfc1918 =
        start_redirecting_issuer("https://10.0.0.1/.well-known/openid-configuration").await;
    assert_generic_refusal(&base, &key, &format!("http://{to_rfc1918}"), &["10.0.0.1"]).await;
}

/// Plain `http` is accepted only to loopback, on every hop — so a redirect
/// cannot downgrade the fetch to cleartext toward any other host, public or
/// allow-listed.
#[tokio::test]
async fn oidc_discovery_refuses_a_redirect_to_plain_http_off_loopback() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    // A public address the guard itself would allow: only the scheme rule
    // stands between this redirect and a cleartext request.
    let downgrade =
        start_redirecting_issuer("http://1.1.1.1/.well-known/openid-configuration").await;
    assert_generic_refusal(&base, &key, &format!("http://{downgrade}"), &["1.1.1.1"]).await;
}

/// The oracle half of the finding: a failing issuer's body used to come back
/// verbatim in the error.
#[tokio::test]
async fn oidc_discovery_does_not_echo_the_upstream_body() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let issuer = start_issuer(|| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "internal-secret-sentinel",
        )
            .into_response()
    })
    .await;
    assert_generic_refusal(
        &base,
        &key,
        &format!("http://{issuer}"),
        &["internal-secret-sentinel", "500"],
    )
    .await;
}
