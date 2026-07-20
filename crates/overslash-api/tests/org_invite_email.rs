//! Integration test for the org-invite notification email.
//!
//! Boots the API with a capturing [`Mailer`] in place of the production
//! Resend mailer, fires `POST /v1/org-invites`, and asserts that exactly
//! one `EmailMessage` was sent with the expected fields populated.
//!
//! Mirrors the structure of [`overslash_managed_signin::invite_create_list_revoke_round_trip`]
//! for the bootstrap path, and stays decoupled from a live Resend instance
//! by intercepting at the [`Mailer`] trait (rather than at the HTTP level
//! like `email_smoke.rs`) — that gives the test direct access to the typed
//! message instead of a serialized JSON body.

use crate::common;

use std::sync::Arc;

use async_trait::async_trait;
use overslash_core::email::{EmailMessage, Mailer, MailerError};
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[derive(Default)]
struct CapturedMailer {
    sends: Mutex<Vec<EmailMessage>>,
}

#[async_trait]
impl Mailer for CapturedMailer {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailerError> {
        self.sends.lock().await.push(msg);
        Ok(())
    }
}

#[tokio::test]
async fn create_invite_sends_notification_email() {
    let pool = common::test_pool().await;
    let mailer = Arc::new(CapturedMailer::default());
    let (addr, client) = common::start_api_with_mailer(pool, mailer.clone(), |_| {}).await;
    let base = format!("http://{addr}");
    let (_, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let created: Value = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "newhire@example.com", "role": "member" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["email"], "newhire@example.com");
    assert_eq!(created["role"], "member");
    assert_eq!(created["status"], "pending");

    let sends = mailer.sends.lock().await;
    assert_eq!(
        sends.len(),
        1,
        "exactly one invite email should be sent; got {sends:?}"
    );
    let msg = &sends[0];

    assert_eq!(msg.to, "newhire@example.com");
    assert!(
        msg.subject.contains("TestOrg"),
        "subject should name the inviting org, got: {}",
        msg.subject
    );
    assert!(
        msg.html.contains("TestOrg"),
        "body should name the inviting org, got: {}",
        msg.html
    );
    assert!(
        msg.html.contains("member"),
        "body should mention the invited role, got: {}",
        msg.html
    );
    // Org-invite is transactional → no unsubscribe wiring.
    assert!(
        !msg.html.to_lowercase().contains("unsubscribe"),
        "transactional invite email must not include an unsubscribe link, got: {}",
        msg.html
    );
    assert!(
        !msg.headers.contains_key("List-Unsubscribe"),
        "transactional invite email must not carry List-Unsubscribe header, got: {:?}",
        msg.headers
    );
}

#[tokio::test]
async fn duplicate_invite_does_not_send_second_email() {
    // The handler returns 409 on the duplicate (the unique partial index in
    // migration 066 enforces "one pending invite per (org, email)"). We must
    // not still fire a second email for the duplicate attempt.
    let pool = common::test_pool().await;
    let mailer = Arc::new(CapturedMailer::default());
    let (addr, client) = common::start_api_with_mailer(pool, mailer.clone(), |_| {}).await;
    let base = format!("http://{addr}");
    let (_, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let ok = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "dup@example.com", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    let conflict = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "dup@example.com", "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 409);

    let sends = mailer.sends.lock().await;
    assert_eq!(
        sends.len(),
        1,
        "duplicate-invite 409 must not fire a second email; got {sends:?}"
    );
}
