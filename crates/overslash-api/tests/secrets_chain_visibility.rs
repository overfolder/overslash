//! End-to-end coverage for identity-owned secrets + bearer-mode visibility.
//!
//! Two agents under the same user each PUT a different secret. Each
//! agent's bearer-mode list must return only its own; their parent user
//! (session) must see both via the subtree walk; the admin sees every
//! row in the org. Values must never appear in the wire payload under
//! any auth shape.

#![allow(clippy::disallowed_methods)]

mod common;

use overslash_api::services::jwt;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

const SIGNING_KEY_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn mint_session_cookie(org_id: Uuid, identity_id: Uuid) -> String {
    let secret = hex::decode(SIGNING_KEY_HEX).expect("valid hex");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "session-test@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(identity_id),
        mcp_client_id: None,
    };
    jwt::mint(&secret, &claims).expect("mint jwt")
}

/// Create a child identity under `parent_id` via the admin API key, return
/// its id and a fresh identity-bound API key for it.
async fn create_child_with_key(
    base: &str,
    client: &reqwest::Client,
    org_id: Uuid,
    parent_id: Uuid,
    admin_key: &str,
    name: &str,
    kind: &str,
) -> (Uuid, String) {
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "name": name,
            "kind": kind,
            "parent_id": parent_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_id: Uuid = ident["id"]
        .as_str()
        .unwrap_or_else(|| panic!("identity create failed: {ident}"))
        .parse()
        .unwrap();

    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": ident_id,
            "name": format!("{name}-key"),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key_resp["key"]
        .as_str()
        .unwrap_or_else(|| panic!("api-key create failed: {key_resp}"))
        .to_string();

    (ident_id, api_key)
}

fn assert_no_value_field(rows: &[Value]) {
    for row in rows {
        let obj = row.as_object().expect("row is object");
        for forbidden in [
            "value",
            "encrypted_value",
            "secret",
            "ciphertext",
            "plaintext",
            "encrypted",
        ] {
            assert!(
                !obj.contains_key(forbidden),
                "list response leaked field {forbidden:?}: {row}"
            );
        }
    }
}

#[tokio::test]
async fn agents_see_only_their_own_subtree_secrets() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");

    // Bootstrap creates: org admin, "test-user" user, "test-agent" agent.
    let (org_id, _agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Find the user identity created by bootstrap (parent of "test-agent").
    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = identities
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "user" && i["name"] == "test-user")
        .expect("test-user")["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Two new agents under the same user. The default bootstrap agent is
    // ignored — we want clean A1/A2 under U for the assertions.
    let (a1_id, a1_key) =
        create_child_with_key(&base, &client, org_id, user_id, &admin_key, "a1", "agent").await;
    let (a2_id, a2_key) =
        create_child_with_key(&base, &client, org_id, user_id, &admin_key, "a2", "agent").await;

    // A1 owns secret_a; A2 owns secret_b. Each PUT is via the agent's
    // own bearer, so `owner_identity_id` is set to that agent's id.
    let r1 = client
        .put(format!("{base}/v1/secrets/secret_a"))
        .header("Authorization", format!("Bearer {a1_key}"))
        .json(&json!({"value": "alpha"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200, "a1 put: {:?}", r1.text().await);

    let r2 = client
        .put(format!("{base}/v1/secrets/secret_b"))
        .header("Authorization", format!("Bearer {a2_key}"))
        .json(&json!({"value": "beta"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200, "a2 put: {:?}", r2.text().await);

    // ── A1's bearer-mode list: sees secret_a only ───────────────────────
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("Authorization", format!("Bearer {a1_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<Value> = resp.json().await.unwrap();
    let names: Vec<&str> = body.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["secret_a"], "A1 should see only secret_a");
    // Bearer narrow shape — confirm contract.
    assert!(body[0]["version_count"].is_i64());
    assert!(body[0]["last_rotated_at"].is_string());
    assert!(
        !body[0]
            .as_object()
            .unwrap()
            .contains_key("owner_identity_id"),
        "bearer narrow shape must not surface owner",
    );
    assert_no_value_field(&body);

    // ── A2's bearer-mode list: sees secret_b only ───────────────────────
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("Authorization", format!("Bearer {a2_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<Value> = resp.json().await.unwrap();
    let names: Vec<&str> = body.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["secret_b"], "A2 should see only secret_b");
    assert_no_value_field(&body);

    // ── Admin (bearer org-admin key) sees every row ─────────────────────
    // Admin is_org_admin short-circuits the visibility CTE entirely; this
    // is the privileged path most likely to silently regress.
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<Value> = resp.json().await.unwrap();
    let mut admin_names: Vec<&str> = body.iter().map(|r| r["name"].as_str().unwrap()).collect();
    admin_names.sort();
    assert!(
        admin_names.contains(&"secret_a") && admin_names.contains(&"secret_b"),
        "admin must see every row in the org, got: {admin_names:?}",
    );
    assert_no_value_field(&body);

    // ── Parent user (session): sees both via subtree walk ───────────────
    let cookie = mint_session_cookie(org_id, user_id);
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "user list: {:?}", resp.text().await);
    let body: Vec<Value> = resp.json().await.unwrap();
    let mut names: Vec<&str> = body.iter().map(|r| r["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["secret_a", "secret_b"],
        "user U should see both descendants' secrets",
    );
    // Dashboard shape — owner column must be present and point at A1 / A2.
    let row_a = body.iter().find(|r| r["name"] == "secret_a").unwrap();
    let row_b = body.iter().find(|r| r["name"] == "secret_b").unwrap();
    assert_eq!(row_a["owner_identity_id"], a1_id.to_string());
    assert_eq!(row_b["owner_identity_id"], a2_id.to_string());
    assert_no_value_field(&body);

    // ── Sibling isolation: A1 cannot view detail of A2's secret ─────────
    // Detail stays session-only by design — agents that try see 401 from
    // the SessionAuth extractor before any visibility check runs.
    let resp = client
        .get(format!("{base}/v1/secrets/secret_b"))
        .header("Authorization", format!("Bearer {a1_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "agents must not reach detail endpoint");

    // ── Sibling isolation on writes: A1 cannot rotate A2's secret ───────
    // Without the put-path visibility gate, the COALESCE on owner would
    // preserve A2 as the slot owner, but A1's value would have replaced
    // A2's — a silent hijack. The handler 404s the same way the read
    // path does, hiding the slot's existence from A1.
    let resp = client
        .put(format!("{base}/v1/secrets/secret_b"))
        .header("Authorization", format!("Bearer {a1_key}"))
        .json(&json!({"value": "hijack"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "A1 must not be able to rotate A2's secret",
    );

    // Confirm A2's value is unchanged by reading via U's session +
    // reveal (admin path is overkill; U is the parent and can reveal).
    let cookie = mint_session_cookie(org_id, user_id);
    let reveal: Value = client
        .post(format!("{base}/v1/secrets/secret_b/versions/1/reveal"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        reveal["value"], "beta",
        "A2's value must survive A1's hijack attempt",
    );
}
