//! An upstream that quotes the request back — `"invalid key <it>"`, a 400
//! repeating the query string — must not return the injected credential to
//! the calling agent, nor to the org's captured audit body (D18). See
//! `services::credential_scrub`.

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};

/// Header-injected. Distinctive enough that a whole-response `contains` means
/// something.
const HEADER_SECRET: &str = "hdr-SEKRET-echo-7c41";
/// Query-injected, and carrying characters the echoed URI percent-encodes.
const QUERY_SECRET: &str = "qry+SEKRET/echo=";

#[tokio::test]
async fn upstream_400_echoing_the_credential_is_redacted() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (api, client) = common::start_api(pool).await;
    let base = format!("http://{api}");
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let ok = |r: reqwest::Response| async move {
        let status = r.status();
        assert!(status.is_success(), "{status}: {}", r.text().await.unwrap());
    };
    ok(client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap())
    .await;
    ok(client
        .patch(format!("{base}/v1/orgs/{org_id}/audit-settings"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"response_body_mode": "errors_only"}))
        .send()
        .await
        .unwrap())
    .await;
    for (name, value) in [("echo_hdr", HEADER_SECRET), ("echo_qry", QUERY_SECRET)] {
        ok(client
            .put(format!("{base}/v1/secrets/{name}"))
            .header(common::auth(&key).0, common::auth(&key).1)
            .json(&json!({"value": value}))
            .send()
            .await
            .unwrap())
        .await;
    }

    let body: Value = call(
        &client,
        &base,
        &key,
        &format!("http://{mock}/echo-status/400"),
    )
    .await;
    assert_eq!(body["status"], "called", "{body}");
    assert_eq!(body["result"]["status_code"], 400, "{body}");

    // The upstream really was sent both…
    let sent = common::last_received(mock).await;
    assert_eq!(
        sent["headers"]["x-api-key"],
        format!("Bearer {HEADER_SECRET}")
    );
    assert!(
        sent["uri"].as_str().unwrap().contains("api_key="),
        "query credential not sent: {sent}"
    );

    // …and neither comes back to the agent, in any encoding.
    assert_no_secret(&body.to_string(), "agent response");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(echo["headers"]["x-api-key"], "Bearer [REDACTED]");

    // Nor to the captured audit body.
    let rows: Vec<Value> = client
        .get(format!("{base}/v1/audit?action=action.executed"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r["detail"]["status_code"] == 400)
        .unwrap_or_else(|| panic!("no audit row for the 400: {rows:?}"));
    let captured = row["detail"]["response"]["body"].as_str().unwrap();
    assert!(captured.contains("[REDACTED]"), "{captured}");
    assert_no_secret(&row.to_string(), "audit row");
}

async fn call(client: &Client, base: &str, key: &str, url: &str) -> Value {
    client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(key).0, common::auth(key).1)
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": url,
            "secrets": [
                {"name": "echo_hdr", "inject_as": "header", "header_name": "X-Api-Key",
                 "prefix": "Bearer "},
                {"name": "echo_qry", "inject_as": "query", "query_param": "api_key"},
            ]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn assert_no_secret(haystack: &str, surface: &str) {
    let encoded = urlencoding::encode(QUERY_SECRET);
    for needle in [HEADER_SECRET, QUERY_SECRET, encoded.as_ref()] {
        assert!(
            !haystack.contains(needle),
            "{surface} leaked `{needle}`: {haystack}"
        );
    }
}
