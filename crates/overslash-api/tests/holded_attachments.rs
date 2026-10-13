//! Holded attachments: a staged upload goes out as a `multipart/form-data`
//! file part, the one encoding Holded's attachment and inbox endpoints read.
//!
//! What is worth proving end to end:
//!
//!   1. the reviewer sees the file as the gateway stored it, and nothing
//!      persisted with the approval holds its bytes;
//!   2. the replay after approval re-encodes the JSON it carried as a form,
//!      with the exact bytes in one `file` part and no base64 anywhere;
//!   3. a user's own call (no approval) takes the inline dial path to the same
//!      wire shape.

use base64::Engine as _;
use reqwest::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common::{self, auth};
use crate::holded::{SeenLog, call, setup, start_mock_holded};

const INVOICE: &str = "6410a1b2c3d4e5f600000002";

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Let the agent stage uploads without an approval, as Allow & Remember would.
async fn allow_uploads(base: &str, client: &Client, admin_key: &str) {
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header(auth(admin_key).0, auth(admin_key).1)
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
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({"identity_id": agent_id, "action_pattern": "overslash:upload_file:*"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "grant: {}", resp.status());
}

/// Mint through `overslash:upload_file`, push the bytes, return the id.
async fn stage(base: &str, client: &Client, key: &str, filename: &str, bytes: &[u8]) -> String {
    let minted: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(key).0, auth(key).1)
        .json(&json!({
            "service": "overslash",
            "action": "upload_file",
            "params": {
                "filename": filename,
                "size_bytes": bytes.len(),
                "content_type": "application/pdf",
            },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let result = &minted["result"]["body"];
    let minted: Value = result
        .as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| result.clone());
    let url = minted["upload_url"]
        .as_str()
        .unwrap_or_else(|| panic!("mint failed: {minted}"));
    let pushed = Client::new()
        .put(url)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(pushed.status(), 201, "push failed");
    minted["upload_id"].as_str().unwrap().to_string()
}

/// The one request the mock saw on `path`, asserted to be a form carrying
/// `bytes` as its `file` part.
fn assert_form_upload(seen: &SeenLog, path: &str, field: &str, filename: &str, bytes: &[u8]) {
    let requests = seen.lock().unwrap().clone();
    let posts: Vec<_> = requests
        .iter()
        .filter(|r| r.method == "POST" && r.path == path)
        .collect();
    assert_eq!(posts.len(), 1, "exactly one upload: {requests:?}");
    let req = posts[0];

    let ct = req.content_type.as_deref().unwrap_or_default();
    let boundary = ct
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap_or_else(|| panic!("not a form: {ct:?}"));

    let mut expected = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; \
         filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    expected.extend_from_slice(bytes);
    expected.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    assert_eq!(
        req.raw, expected,
        "the form is exactly one file part with the staged bytes"
    );
    assert_eq!(
        req.authorization.as_deref(),
        Some("Bearer hld_test_token_123")
    );
}

#[tokio::test]
async fn an_approved_attachment_replays_as_a_form_with_the_staged_bytes() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_holded().await;
    let (base, client, agent_key, admin_key) = setup(pool.clone(), mock, "admin").await;
    allow_uploads(&base, &client, &admin_key).await;

    // Not valid UTF-8 on purpose: the body is bytes end to end, not a string.
    let bytes = b"%PDF-1.7\x00\x9f\x92\x96\xff receipt".to_vec();
    let id = stage(&base, &client, &agent_key, "ticket-0042.pdf", &bytes).await;

    let pending = call(
        &base,
        &client,
        &agent_key,
        "attach_invoice_file",
        json!({ "invoiceId": INVOICE, "file": [{ "upload_id": id }] }),
    )
    .await;
    assert_eq!(pending["status"], json!("pending_approval"), "{pending}");

    let file_row = pending["disclosed_fields"]
        .as_array()
        .and_then(|f| f.iter().find(|f| f["label"] == "File"))
        .and_then(|f| f["value"].as_str())
        .unwrap_or_else(|| panic!("a File disclosure row: {pending}"))
        .to_string();
    assert!(file_row.contains("ticket-0042.pdf"), "{file_row}");
    assert!(
        file_row.contains(&format!("{} bytes", bytes.len())),
        "{file_row}"
    );
    assert!(file_row.contains(&sha_hex(&bytes)[..12]), "{file_row}");
    let rendered = pending["disclosed_fields"].to_string();
    assert!(
        rendered.contains("F-2026-0042"),
        "resolves the invoice: {rendered}"
    );

    let approval_id = pending["approval_id"].as_str().unwrap();
    let payload = sqlx::query_scalar!(
        "SELECT replay_payload::text FROM approvals WHERE id = $1::uuid",
        approval_id.parse::<uuid::Uuid>().unwrap(),
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .unwrap_or_default();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert!(!payload.contains(&b64), "bytes leaked into replay_payload");

    let resolved = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resolved.status(), 200);
    let replayed = client
        .post(format!("{base}/v1/approvals/{approval_id}/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(replayed.status(), 200, "{}", replayed.text().await.unwrap());

    assert_form_upload(
        &seen,
        &format!("/api/v2/invoices/{INVOICE}/attachments"),
        "file",
        "ticket-0042.pdf",
        &bytes,
    );
}

/// A user approves its own calls, so this is the inline dial path — and the
/// inbox names its part `document`, not `file`.
#[tokio::test]
async fn a_user_upload_to_the_inbox_goes_out_inline_as_a_form() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_holded().await;
    let (base, client, _agent_key, admin_key) = setup(pool, mock, "admin").await;

    let bytes = b"%PDF-1.4 supplier bill".to_vec();
    let id = stage(&base, &client, &admin_key, "bill.pdf", &bytes).await;

    let body = call(
        &base,
        &client,
        &admin_key,
        "upload_inbox",
        json!({ "document": [{ "upload_id": id }] }),
    )
    .await;
    assert_eq!(body["status"], json!("called"), "{body}");

    assert_form_upload(&seen, "/api/v2/inbox", "document", "bill.pdf", &bytes);
}

/// Only a template can ask for a form to be built. A raw HTTP call that
/// carries a multipart body of its own declares no staged fields, so its bytes
/// and boundary go out exactly as the caller wrote them — never parsed as the
/// JSON a template form is held as.
#[tokio::test]
async fn a_raw_multipart_call_passes_through_untouched() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_holded().await;
    let (base, client, _agent_key, admin_key) = setup(pool, mock, "admin").await;

    let raw = "--b1\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n--b1--\r\n";
    let resp: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "service": "http",
            "method": "POST",
            "url": format!("http://{mock}/raw-form"),
            "headers": {"Content-Type": "multipart/form-data; boundary=b1"},
            "body": raw,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], json!("called"), "{resp}");

    let req = seen.lock().unwrap().last().cloned().expect("mock saw none");
    assert_eq!(req.path, "/raw-form");
    assert_eq!(
        req.content_type.as_deref(),
        Some("multipart/form-data; boundary=b1")
    );
    assert_eq!(req.raw, raw.as_bytes());
}
