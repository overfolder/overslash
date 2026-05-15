//! End-to-end smoke test for the transactional-email pipeline.
//!
//! Spins up an in-process axum mock that impersonates Resend's
//! `POST /emails` endpoint, points a real [`ResendMailer`] at it via
//! `with_base_url`, renders the bundled `TEST_TEMPLATE_HTML` against a
//! parameter map, and asserts the resulting HTTP request carries the
//! correct bearer token plus a JSON body whose `html` field contains the
//! substituted placeholders.
//!
//! Proves the config → template-render → HTTP path that future callers
//! (billing receipts, welcome, DLQ digest) will rely on, without ever
//! touching the live Resend API.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use overslash_api::services::email::ResendMailer;
use overslash_core::email::{
    EmailMessage, Mailer, TEST_TEMPLATE_HTML, TEST_TEMPLATE_SUBJECT, render,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Default, Clone)]
struct CapturedRequest {
    auth_header: Option<String>,
    body: Option<Value>,
}

type SharedCapture = Arc<Mutex<Vec<CapturedRequest>>>;

async fn start_mock_resend() -> (String, SharedCapture) {
    let captured: SharedCapture = Arc::new(Mutex::new(Vec::new()));

    async fn handler(
        State(captured): State<SharedCapture>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let auth_header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        captured.lock().await.push(CapturedRequest {
            auth_header,
            body: Some(body),
        });
        Json(json!({ "id": "em_smoke_test" }))
    }

    let app = Router::new()
        .route("/emails", post(handler))
        .with_state(captured.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}"), captured)
}

#[tokio::test]
async fn resend_mailer_sends_rendered_template() {
    let (base_url, captured) = start_mock_resend().await;

    let mailer = ResendMailer::with_base_url(
        reqwest::Client::new(),
        "re_test_smoke_key".to_string(),
        "no-reply@overslash.test".to_string(),
        Some("support@overslash.test".to_string()),
        base_url,
    );

    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("user_name".into(), json!("Ada"));
    params.insert("greeting".into(), json!("Welcome to Overslash"));
    let rendered_html = render(TEST_TEMPLATE_HTML, &params);

    let msg = EmailMessage {
        from: String::new(),
        to: "ada@example.com".to_string(),
        subject: TEST_TEMPLATE_SUBJECT.to_string(),
        html: rendered_html.clone(),
        reply_to: None,
        headers: HashMap::new(),
    };

    mailer.send(msg).await.expect("send succeeded");

    let captured = captured.lock().await;
    assert_eq!(captured.len(), 1, "exactly one request should be captured");
    let req = &captured[0];

    assert_eq!(
        req.auth_header.as_deref(),
        Some("Bearer re_test_smoke_key"),
        "Authorization header should carry the bearer token verbatim"
    );

    let body = req.body.as_ref().expect("captured body");
    assert_eq!(body["from"], json!("no-reply@overslash.test"));
    assert_eq!(body["to"], json!("ada@example.com"));
    assert_eq!(body["subject"], json!(TEST_TEMPLATE_SUBJECT));
    assert_eq!(body["reply_to"], json!("support@overslash.test"));

    let html = body["html"].as_str().expect("html field is a string");
    assert!(
        html.contains("Hello Ada,"),
        "rendered template should substitute user_name: {html}"
    );
    assert!(
        html.contains("Welcome to Overslash"),
        "rendered template should include greeting from optional segment: {html}"
    );
    assert!(
        !html.contains("{user_name}"),
        "rendered template should not contain unresolved placeholders: {html}"
    );
}

#[tokio::test]
async fn resend_mailer_surfaces_upstream_errors() {
    // Mock that always returns 422 with a Resend-style error envelope. Proves
    // the impl propagates non-success responses as MailerError::Upstream
    // rather than treating them as success.
    let app = Router::new().route(
        "/emails",
        post(|| async {
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "message": "Invalid `to` field", "statusCode": 422 })),
            )
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base_url = format!("http://{addr}");

    let mailer = ResendMailer::with_base_url(
        reqwest::Client::new(),
        "re_test".to_string(),
        "no-reply@overslash.test".to_string(),
        None,
        base_url,
    );
    let err = mailer
        .send(EmailMessage {
            from: String::new(),
            to: "bad".into(),
            subject: "x".into(),
            html: "<p>x</p>".into(),
            reply_to: None,
            headers: HashMap::new(),
        })
        .await
        .expect_err("upstream 422 should surface as MailerError::Upstream");

    match err {
        overslash_core::email::MailerError::Upstream { status, body } => {
            assert_eq!(status, 422);
            assert!(
                body.contains("Invalid `to` field"),
                "upstream body should be propagated: {body}"
            );
        }
        other => panic!("unexpected MailerError variant: {other:?}"),
    }
}
