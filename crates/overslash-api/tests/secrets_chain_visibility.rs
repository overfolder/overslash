//! End-to-end coverage for per-user secret vaults + bearer-mode visibility.
//!
//! Two agents under the same user each PUT a different secret. Both land in
//! their user's vault, so both agents (and the user's session) see both. An
//! agent of a *different* user sees neither, and its same-named write lands
//! in its own vault without touching theirs. The admin sees every row in the
//! org. Values must never appear in the wire payload under any auth shape.

#![allow(clippy::disallowed_methods)]

use crate::common;

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
        jti: None,
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
async fn agents_share_their_users_vault_and_nobody_elses() {
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

    // A1 writes secret_a; A2 writes secret_b. An agent's vault is its owner
    // user's, so both land in U's vault.
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

    // A second user V with an agent B: a different vault.
    let v: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "v", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let v_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    let (_b_id, b_key) =
        create_child_with_key(&base, &client, org_id, v_id, &admin_key, "b", "agent").await;

    let list = |key: String| {
        let client = client.clone();
        let base = base.clone();
        async move {
            let resp = client
                .get(format!("{base}/v1/secrets"))
                .header("Authorization", format!("Bearer {key}"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: Vec<Value> = resp.json().await.unwrap();
            assert_no_value_field(&body);
            let mut names: Vec<String> = body
                .iter()
                .map(|r| r["name"].as_str().unwrap().to_string())
                .collect();
            names.sort();
            (names, body)
        }
    };

    // ── Both of U's agents see U's whole vault ──────────────────────────
    let (names, body) = list(a1_key.clone()).await;
    assert_eq!(names, ["secret_a", "secret_b"], "A1 sees U's vault");
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
    let (names, _) = list(a2_key.clone()).await;
    assert_eq!(names, ["secret_a", "secret_b"], "A2 sees U's vault");

    // ── Another user's agent sees none of it ────────────────────────────
    let (names, _) = list(b_key.clone()).await;
    assert!(names.is_empty(), "B must not see U's vault: {names:?}");

    // ── Admin (bearer org-admin key) sees every row ─────────────────────
    let (names, _) = list(admin_key.clone()).await;
    assert!(
        names.contains(&"secret_a".to_string()) && names.contains(&"secret_b".to_string()),
        "admin must see every row in the org, got: {names:?}",
    );

    // ── U's session: both, owned by U ───────────────────────────────────
    let cookie = mint_session_cookie(org_id, user_id);
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("cookie", format!("__Host-oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "user list: {:?}", resp.text().await);
    let body: Vec<Value> = resp.json().await.unwrap();
    let mut names: Vec<&str> = body.iter().map(|r| r["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(names, vec!["secret_a", "secret_b"]);
    for row in &body {
        assert_eq!(row["owner_identity_id"], user_id.to_string());
        assert_eq!(row["scope"], "user");
        assert_eq!(
            row["path"],
            format!("{user_id}/{}", row["name"].as_str().unwrap())
        );
    }
    let _ = (a1_id, a2_id);
    assert_no_value_field(&body);

    // ── Agents never reach the detail endpoint ──────────────────────────
    let resp = client
        .get(format!("{base}/v1/secrets/secret_b"))
        .header("Authorization", format!("Bearer {a1_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "agents must not reach detail endpoint");

    // ── B writing the same name fills B's own vault, not U's ────────────
    let resp = client
        .put(format!("{base}/v1/secrets/secret_b"))
        .header("Authorization", format!("Bearer {b_key}"))
        .json(&json!({"value": "hijack"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(
        v["version"], 1,
        "a fresh secret in B's vault, not v2 of U's"
    );
    // …nor can B address U's vault explicitly.
    let resp = client
        .put(format!("{base}/v1/secrets/secret_b?owner={user_id}"))
        .header("Authorization", format!("Bearer {b_key}"))
        .json(&json!({"value": "hijack"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let reveal: Value = client
        .post(format!("{base}/v1/secrets/secret_b/versions/1/reveal"))
        .header("cookie", format!("__Host-oss_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reveal["value"], "beta", "U's value must survive B's write");
}
