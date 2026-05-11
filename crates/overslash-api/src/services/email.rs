//! HTTP-backed transactional-email providers.
//!
//! The provider-agnostic `Mailer` trait lives in `overslash_core::email`.
//! This module hosts the impls that actually mint HTTP requests, so the
//! shared `reqwest::Client` and `tracing` integration stay in `overslash-api`
//! alongside other outbound-HTTP services (Stripe, OAuth upstreams).
//!
//! `build_mailer` is the canonical constructor: it inspects [`Config`] and
//! returns either a real provider or the [`NoopMailer`] fallback.

use std::sync::Arc;

use async_trait::async_trait;
use overslash_core::email::{EmailMessage, Mailer, MailerError, NoopMailer};
use serde::Serialize;
use serde_json::Value;

use crate::config::Config;

/// Default base URL for Resend. Tests override the constructor's `base_url`
/// argument directly so this stays a compile-time constant.
const RESEND_BASE_URL: &str = "https://api.resend.com";

/// Resend (https://resend.com) `POST /emails` implementation.
///
/// Single shared `reqwest::Client` is injected so connections are pooled
/// with the rest of the API. The constructor takes the API key by value —
/// callers read it from `Config::email_api_key` once at app boot.
pub struct ResendMailer {
    client: reqwest::Client,
    api_key: String,
    default_from: String,
    default_reply_to: Option<String>,
    base_url: String,
}

impl ResendMailer {
    pub fn new(
        client: reqwest::Client,
        api_key: String,
        default_from: String,
        default_reply_to: Option<String>,
    ) -> Self {
        Self::with_base_url(
            client,
            api_key,
            default_from,
            default_reply_to,
            RESEND_BASE_URL.to_string(),
        )
    }

    pub fn with_base_url(
        client: reqwest::Client,
        api_key: String,
        default_from: String,
        default_reply_to: Option<String>,
        base_url: String,
    ) -> Self {
        Self {
            client,
            api_key,
            default_from,
            default_reply_to,
            base_url,
        }
    }
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    html: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<&'a str>,
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailerError> {
        // Caller can override defaults per-message; if `from` is empty fall
        // back to the configured `EMAIL_FROM`. `reply_to` is purely
        // additive — empty Option means "let provider apply its default".
        let from = if msg.from.is_empty() {
            self.default_from.as_str()
        } else {
            msg.from.as_str()
        };
        let reply_to = msg.reply_to.as_deref().or(self.default_reply_to.as_deref());

        let body = ResendRequest {
            from,
            to: &msg.to,
            subject: &msg.subject,
            html: &msg.html,
            reply_to,
        };

        let url = format!("{}/emails", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| MailerError::Transport(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let upstream_body = resp.text().await.unwrap_or_default();
        // Surface useful upstream metadata when the provider returns a JSON
        // error envelope, otherwise pass the raw body through.
        let body_for_err = match serde_json::from_str::<Value>(&upstream_body) {
            Ok(v) => v.to_string(),
            Err(_) => upstream_body,
        };
        Err(MailerError::Upstream {
            status: status.as_u16(),
            body: body_for_err,
        })
    }
}

/// Pick the mailer impl matching `config.email_provider`.
///
/// When `EMAIL_PROVIDER` is unset, returns [`NoopMailer`] so local dev /
/// self-hosted boots without provider credentials. When it *is* set,
/// `Config::validate_env` has already enforced that `EMAIL_API_KEY` and
/// `EMAIL_FROM` are present — so an unknown provider value here is an
/// operator typo and we fail fast rather than silently drop mail.
pub fn build_mailer(config: &Config, client: reqwest::Client) -> Arc<dyn Mailer> {
    match config.email_provider.as_deref() {
        None => Arc::new(NoopMailer),
        Some("resend") => {
            // validate_env enforces EMAIL_API_KEY + EMAIL_FROM when
            // EMAIL_PROVIDER is set. Use expect() so a regression in
            // validation surfaces as an obvious boot panic, not silent
            // mail-drop.
            let api_key = config.email_api_key.clone().expect(
                "EMAIL_API_KEY required when EMAIL_PROVIDER is set (validate_env regression)",
            );
            let from = config
                .email_from
                .clone()
                .expect("EMAIL_FROM required when EMAIL_PROVIDER is set (validate_env regression)");
            tracing::info!(from = %from, "Email provider: resend");
            Arc::new(ResendMailer::new(
                client,
                api_key,
                from,
                config.email_reply_to.clone(),
            ))
        }
        Some(other) => panic!(
            "Unknown EMAIL_PROVIDER={other:?} — supported values: \"resend\". Unset the variable to disable email."
        ),
    }
}
