//! Email attachments through gateway-staged uploads (`x-overslash-staged-upload`).
//!
//! The flow under test, end to end against the in-process overfwd mock:
//! `overslash:upload_file` mints a single-use URL → the raw bytes are PUT to
//! `/v1/uploads/{token}` → `email:send` names `{upload_id}` → the approval
//! discloses the *stored* descriptor → on replay the gateway inlines
//! `{filename, content_type, content_base64}` into the body overfwd receives.
//!
//! And the abuse bounds that come with holding bytes: exact-size and digest
//! enforcement on the push, per-identity quotas with forced eviction of the
//! caller's own oldest uploads, pins that protect an upload a pending approval
//! names, and owner scoping on references.
//!
//! Run with `--test-threads=4` (see CLAUDE.md).

#![allow(clippy::disallowed_methods)]

use base64::Engine as _;
use reqwest::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common;
use crate::email_overfwd::{
    GATEWAY_KEY, MAILBOX_PASS, MAILBOX_USER, Sink, setup_email_instance_configured,
    start_mock_overfwd,
};

struct Env {
    base: String,
    agent_key: String,
    admin_key: String,
    sink: Sink,
    pool: sqlx::PgPool,
}

/// An email instance on the mock, plus an agent allowed to stage uploads
/// without an approval (a user would grant this once with Allow & Remember).
async fn setup<F>(customize: F) -> Env
where
    F: FnOnce(&mut overslash_api::config::Config),
{
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let body = json!({
        "template_key": "email",
        "name": "email",
        "url": gateway_url,
        "user_level": false,
        "status": "active",
        "credentials": { "mailbox_pass": "mailbox_pass" },
        "config": { "mailbox_user": MAILBOX_USER },
    });
    let (base, agent_key, admin_key, _instance) = setup_email_instance_configured(
        pool.clone(),
        &[
            ("overfwd_gateway_key", GATEWAY_KEY),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        None,
        body,
        customize,
    )
    .await;

    let identities: Vec<Value> = Client::new()
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = identities
        .iter()
        .find(|i| i["name"] == "test-agent")
        .and_then(|i| i["id"].as_str())
        .expect("test-agent identity")
        .to_string();
    let resp = Client::new()
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"identity_id": agent_id, "action_pattern": "overslash:upload_file:*"}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "grant failed: {}",
        resp.status()
    );

    Env {
        base,
        agent_key,
        admin_key,
        sink,
        pool,
    }
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn call(env: &Env, key: &str, body: Value) -> (u16, Value) {
    let resp = Client::new()
        .post(format!("{}/v1/actions/call", env.base))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Mint through the platform action. Returns the raw response on refusal so
/// quota tests can read the 429 envelope.
async fn mint(env: &Env, key: &str, params: Value) -> (u16, Value) {
    let (status, body) = call(
        env,
        key,
        json!({"service": "overslash", "action": "upload_file", "params": params}),
    )
    .await;
    if status != 200 {
        return (status, body);
    }
    let result = &body["result"]["body"];
    let parsed = result
        .as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| result.clone());
    (status, parsed)
}

async fn put(url: &str, bytes: &[u8]) -> (u16, Value) {
    let resp = Client::new()
        .put(url)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// Mint and push `bytes`; returns the upload id.
async fn stage(env: &Env, key: &str, filename: &str, bytes: &[u8]) -> String {
    let (status, minted) = mint(
        env,
        key,
        json!({"filename": filename, "size_bytes": bytes.len(), "content_type": "application/pdf"}),
    )
    .await;
    assert_eq!(status, 200, "mint failed: {minted}");
    let (status, stored) = put(minted["upload_url"].as_str().unwrap(), bytes).await;
    assert_eq!(status, 201, "push failed: {stored}");
    assert_eq!(stored["sha256"].as_str(), Some(sha_hex(bytes).as_str()));
    minted["upload_id"].as_str().unwrap().to_string()
}

fn send_params(upload_ids: &[&str]) -> Value {
    json!({
        "service": "email",
        "action": "send",
        "params": {
            "from": MAILBOX_USER,
            "to": ["boss@example.com"],
            "subject": "Q3 deck",
            "text": "Attached.",
            "attachments": upload_ids.iter().map(|id| json!({"upload_id": id})).collect::<Vec<_>>(),
        }
    })
}

#[tokio::test]
async fn gated_send_discloses_descriptor_and_inlines_bytes_on_replay() {
    let env = setup(|_| {}).await;
    let bytes = b"%PDF-1.7 quarterly numbers".to_vec();
    let id = stage(&env, &env.agent_key, "q3-deck.pdf", &bytes).await;

    let (status, pending) = call(&env, &env.agent_key, send_params(&[&id])).await;
    assert_eq!(status, 202, "send should be gated: {pending}");
    assert_eq!(pending["status"], "pending_approval");

    // The reviewer sees the file as the gateway stored it.
    let disclosed = pending["disclosed_fields"].as_array().unwrap();
    let attachments = disclosed
        .iter()
        .find(|f| f["label"] == "Attachments")
        .and_then(|f| f["value"].as_str())
        .expect("an Attachments disclosure row");
    assert!(attachments.contains("q3-deck.pdf"), "{attachments}");
    assert!(
        attachments.contains(&format!("{} bytes", bytes.len())),
        "{attachments}"
    );
    assert!(
        attachments.contains(&sha_hex(&bytes)[..12]),
        "{attachments}"
    );
    assert!(env.sink.lock().unwrap().is_empty(), "gated before dialing");

    // Nothing persisted with the approval holds the bytes.
    let approval_id = pending["approval_id"].as_str().unwrap();
    let approval: Value = Client::new()
        .get(format!("{}/v1/approvals/{approval_id}", env.base))
        .header("Authorization", format!("Bearer {}", env.admin_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert!(!approval.to_string().contains(&b64));
    let payload = sqlx::query_scalar!(
        "SELECT replay_payload::text FROM approvals WHERE id = $1::uuid",
        approval_id.parse::<uuid::Uuid>().unwrap(),
    )
    .fetch_one(&env.pool)
    .await
    .unwrap()
    .unwrap_or_default();
    assert!(!payload.contains(&b64), "bytes leaked into replay_payload");

    let resp = Client::new()
        .post(format!("{}/v1/approvals/{approval_id}/resolve", env.base))
        .header("Authorization", format!("Bearer {}", env.admin_key))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = Client::new()
        .post(format!("{}/v1/approvals/{approval_id}/call", env.base))
        .header("Authorization", format!("Bearer {}", env.agent_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let captured = env.sink.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/email/send");
    assert_eq!(
        captured[0].body["attachments"],
        json!([{
            "filename": "q3-deck.pdf",
            "content_type": "application/pdf",
            "content_base64": b64,
        }]),
        "overfwd gets exactly its wire shape — no upload_id, no descriptor"
    );
}

#[tokio::test]
async fn user_send_inlines_without_an_approval() {
    // A user is its own approver, so this runs the inline dial path.
    let env = setup(|_| {}).await;
    let bytes = vec![0u8, 159, 146, 150, 255];
    let id = stage(&env, &env.admin_key, "blob.bin", &bytes).await;

    let (status, body) = call(&env, &env.admin_key, send_params(&[&id])).await;
    assert_eq!(status, 200, "{body}");
    let captured = env.sink.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    let sent = captured[0].body["attachments"][0]["content_base64"]
        .as_str()
        .unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(sent)
            .unwrap(),
        bytes,
        "binary bytes survive the round trip exactly"
    );
}

#[tokio::test]
async fn an_upload_resolves_only_under_the_user_who_staged_it() {
    let env = setup(|_| {}).await;
    // Staged by the org admin; the agent belongs to a different user.
    let id = stage(&env, &env.admin_key, "private.pdf", b"secret").await;
    let (status, body) = call(&env, &env.agent_key, send_params(&[&id])).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.to_string().contains("unknown, expired"), "{body}");
    assert!(env.sink.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_push_must_match_what_was_minted() {
    let env = setup(|_| {}).await;

    // Longer than declared: cut off, and the token is spent.
    let (_, minted) = mint(
        &env,
        &env.agent_key,
        json!({"filename": "a.txt", "size_bytes": 4}),
    )
    .await;
    let url = minted["upload_url"].as_str().unwrap().to_string();
    let (status, _) = put(&url, b"too long").await;
    assert_eq!(status, 413);
    let (status, _) = put(&url, b"abcd").await;
    assert_eq!(status, 404, "a failed push spends the token");

    // Right size, wrong digest.
    let (_, minted) = mint(
        &env,
        &env.agent_key,
        json!({"filename": "b.txt", "size_bytes": 4, "sha256": sha_hex(b"abcd")}),
    )
    .await;
    let (status, _) = put(minted["upload_url"].as_str().unwrap(), b"abce").await;
    assert_eq!(status, 422);

    // Over the per-upload ceiling is refused at mint.
    let (status, body) = mint(
        &env,
        &env.agent_key,
        json!({"filename": "big.bin", "size_bytes": 11 * 1024 * 1024}),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // Failed pushes released their reservations.
    let live = sqlx::query_scalar!("SELECT COUNT(*) FROM staged_uploads")
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(live, Some(0));
}

#[tokio::test]
async fn over_quota_refuses_and_force_evicts_the_oldest_own_upload() {
    let env = setup(|c| c.staged_uploads.identity_max_count = 2).await;
    let first = stage(&env, &env.agent_key, "1.pdf", b"one").await;
    let second = stage(&env, &env.agent_key, "2.pdf", b"two").await;

    let (status, refused) = mint(
        &env,
        &env.agent_key,
        json!({"filename": "3.pdf", "size_bytes": 5}),
    )
    .await;
    assert_eq!(status, 429, "{refused}");
    assert_eq!(refused["error"], "staged_upload_quota_exceeded");
    assert_eq!(refused["evictable_count"], 2);
    assert!(refused["hint"].as_str().unwrap().contains("force"));

    let (status, minted) = mint(
        &env,
        &env.agent_key,
        json!({"filename": "3.pdf", "size_bytes": 5, "force": true}),
    )
    .await;
    assert_eq!(status, 200, "{minted}");
    assert_eq!(
        minted["evicted"],
        json!([first]),
        "exactly the oldest, nothing more"
    );

    // The evicted upload is gone for sending; the survivor still works.
    let (status, _) = call(&env, &env.admin_key, send_params(&[&first])).await;
    assert_eq!(status, 400);
    let remaining = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM staged_uploads WHERE id = $1::uuid",
        second.parse::<uuid::Uuid>().unwrap()
    )
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(remaining, Some(1));
}

#[tokio::test]
async fn an_upload_a_pending_approval_names_is_never_evicted() {
    let env = setup(|c| c.staged_uploads.identity_max_count = 1).await;
    let id = stage(&env, &env.agent_key, "board.pdf", b"minutes").await;
    let (status, _) = call(&env, &env.agent_key, send_params(&[&id])).await;
    assert_eq!(status, 202, "parked behind an approval, which pins it");

    for force in [false, true] {
        let (status, refused) = mint(
            &env,
            &env.agent_key,
            json!({"filename": "other.pdf", "size_bytes": 3, "force": force}),
        )
        .await;
        assert_eq!(status, 429, "force={force}: {refused}");
        assert_eq!(
            refused["evictable_count"], 0,
            "a pinned upload is not a candidate"
        );
    }
}

#[tokio::test]
async fn an_upload_that_vanished_before_replay_fails_without_dialing() {
    let env = setup(|_| {}).await;
    let id = stage(&env, &env.agent_key, "gone.pdf", b"soon gone").await;
    let (_, pending) = call(&env, &env.agent_key, send_params(&[&id])).await;
    let approval_id = pending["approval_id"].as_str().unwrap().to_string();

    // What expiry (or an operator) does to the row while the approval waits.
    sqlx::query!("DELETE FROM staged_uploads")
        .execute(&env.pool)
        .await
        .unwrap();

    Client::new()
        .post(format!("{}/v1/approvals/{approval_id}/resolve", env.base))
        .header("Authorization", format!("Bearer {}", env.admin_key))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    let resp = Client::new()
        .post(format!("{}/v1/approvals/{approval_id}/call", env.base))
        .header("Authorization", format!("Bearer {}", env.agent_key))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("expired"), "{body}");
    assert!(
        env.sink.lock().unwrap().is_empty(),
        "never sends a stub in place of the file"
    );
}

#[tokio::test]
async fn deliver_url_is_refused_for_a_staged_send() {
    let env = setup(|_| {}).await;
    let id = stage(&env, &env.admin_key, "x.pdf", b"x").await;
    let mut body = send_params(&[&id]);
    body["deliver"] = json!("url");
    let (status, resp) = call(&env, &env.admin_key, body).await;
    assert_eq!(status, 400, "{resp}");
    assert!(resp.to_string().contains("staged uploads"), "{resp}");
}

#[tokio::test]
async fn an_empty_attachment_list_sends_a_plain_message() {
    // Nothing to inline, so nothing to stage, pin or buffer: the list goes
    // through untouched and the send behaves like one with no attachments.
    let env = setup(|_| {}).await;
    let (status, body) = call(&env, &env.admin_key, send_params(&[])).await;
    assert_eq!(status, 200, "{body}");
    let captured = env.sink.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].body["attachments"], json!([]));
}
