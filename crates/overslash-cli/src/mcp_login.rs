//! `overslash mcp login` — OAuth 2.1 authorization_code + PKCE flow for
//! the MCP shim, implementing §"Implementation order" step 6 of
//! `docs/design/mcp-oauth-transport.md`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use overslash_mcp::config::McpConfig;

pub async fn run(
    config_path: PathBuf,
    server_flag: Option<String>,
    re_auth: bool,
) -> anyhow::Result<()> {
    let existing = McpConfig::load(&config_path).ok();
    let server_url = resolve_server_url(server_flag, existing.as_ref())?;
    let discovery = discover_as(&server_url)
        .await
        .with_context(|| format!("discovering AS metadata at {server_url}"))?;

    let mut client_id = if re_auth {
        None
    } else {
        existing.as_ref().and_then(|c| c.client_id.clone())
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind 127.0.0.1:0 for OAuth callback")?;
    let bound_addr = listener.local_addr().context("local_addr")?;
    let redirect_uri = format!("http://{bound_addr}/callback");

    if client_id.is_none() {
        let registered = dcr(&discovery.registration_endpoint, &redirect_uri)
            .await
            .context("dynamic client registration")?;
        client_id = Some(registered);
    }
    let client_id = client_id.expect("client_id set by DCR when missing");

    let (verifier, challenge) = generate_pkce();
    let state_value = random_url_safe(32);

    let authorize_url = build_authorize_url(
        &discovery.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &challenge,
        &state_value,
    );

    println!("Opening browser for Overslash login:");
    println!("  {authorize_url}");
    if webbrowser::open(&authorize_url).is_err() {
        println!("(browser launch failed — paste the URL above into a browser yourself)");
    }

    let code = wait_for_callback(listener, &state_value).await?;

    let token_pair = exchange_code(
        &discovery.token_endpoint,
        &code,
        &redirect_uri,
        &client_id,
        &verifier,
    )
    .await
    .context("token exchange")?;

    let cfg = McpConfig {
        server_url: server_url.clone(),
        token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        client_id: Some(client_id),
    };
    cfg.save(&config_path)
        .with_context(|| format!("persist MCP config to {}", config_path.display()))?;

    println!();
    println!("Saved config to {}", config_path.display());
    println!("Add to your MCP client config:");
    println!("  {{ \"command\": \"overslash\", \"args\": [\"mcp\"] }}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Server URL resolution
// ---------------------------------------------------------------------------

fn resolve_server_url(
    flag: Option<String>,
    existing: Option<&McpConfig>,
) -> anyhow::Result<String> {
    if let Some(s) = flag {
        return Ok(normalize_url(&s));
    }
    if let Some(c) = existing {
        return Ok(c.server_url.clone());
    }
    print_prompt("Server URL (e.g. https://acme.overslash.dev): ");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let s = buf.trim();
    if s.is_empty() {
        return Err(anyhow!("server URL is required"));
    }
    Ok(normalize_url(s))
}

fn normalize_url(s: &str) -> String {
    s.trim_end_matches('/').to_string()
}

fn print_prompt(msg: &str) {
    use std::io::Write;
    print!("{msg}");
    let _ = std::io::stdout().flush();
}

// ---------------------------------------------------------------------------
// AS discovery (RFC 8414)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AsMetadata {
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: String,
}

async fn discover_as(server_url: &str) -> anyhow::Result<AsMetadata> {
    let url = format!("{server_url}/.well-known/oauth-authorization-server");
    let resp = reqwest::get(&url).await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "AS metadata request returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json::<AsMetadata>().await?)
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

async fn dcr(endpoint: &str, redirect_uri: &str) -> anyhow::Result<String> {
    let body = serde_json::json!({
        "client_name": "overslash-cli",
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "software_id": "overslash-cli",
        "software_version": env!("CARGO_PKG_VERSION"),
    });
    let resp = reqwest::Client::new()
        .post(endpoint)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("DCR returned {status}: {text}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text)?;
    v.get("client_id")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("DCR response missing client_id: {text}"))
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

fn generate_pkce() -> (String, String) {
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    let verifier = URL_SAFE_NO_PAD.encode(buf);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn random_url_safe(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::rng().fill(buf.as_mut_slice());
    URL_SAFE_NO_PAD.encode(&buf)
}

fn build_authorize_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> String {
    let enc = urlencoding::encode;
    format!(
        "{endpoint}?response_type=code&client_id={}&redirect_uri={}\
         &code_challenge={}&code_challenge_method=S256&scope=mcp&state={}",
        enc(client_id),
        enc(redirect_uri),
        enc(challenge),
        enc(state),
    )
}

// ---------------------------------------------------------------------------
// Localhost callback listener
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

struct CallbackState {
    expected_state: String,
    tx: tokio::sync::Mutex<Option<oneshot::Sender<Result<String, String>>>>,
}

async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> anyhow::Result<String> {
    let (tx, rx) = oneshot::channel::<Result<String, String>>();
    let state = Arc::new(CallbackState {
        expected_state: expected_state.to_string(),
        tx: tokio::sync::Mutex::new(Some(tx)),
    });
    let app = Router::new()
        .route("/callback", get(callback_handler))
        .with_state(state);
    let addr: SocketAddr = listener.local_addr()?;
    tracing::debug!(%addr, "listening for OAuth callback");
    let server = axum::serve(listener, app.into_make_service());
    // A closed browser tab leaves this waiting forever otherwise; five
    // minutes is the OAuth 2.1 recommended ceiling for user consent
    // round-trip time.
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(300));
    tokio::pin!(timeout);
    tokio::select! {
        res = rx => match res {
            Ok(Ok(code)) => Ok(code),
            Ok(Err(e)) => Err(anyhow!("{e}")),
            Err(_) => Err(anyhow!("callback oneshot dropped")),
        },
        _ = server => Err(anyhow!("callback listener exited before code received")),
        _ = &mut timeout => Err(anyhow!(
            "timed out waiting for the OAuth callback (5 minutes) — re-run `overslash mcp login`"
        )),
    }
}

async fn callback_handler(
    State(state): State<Arc<CallbackState>>,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    let outcome = if let Some(err) = q.error {
        Err(format!(
            "authorization failed: {err}{}",
            q.error_description
                .map(|d| format!(" ({d})"))
                .unwrap_or_default()
        ))
    } else if q.state.as_deref() != Some(state.expected_state.as_str()) {
        Err("state mismatch on callback".into())
    } else if let Some(code) = q.code {
        Ok(code)
    } else {
        Err("callback missing code parameter".into())
    };

    let mut guard = state.tx.lock().await;
    if let Some(tx) = guard.take() {
        let _ = tx.send(outcome.clone());
    }
    let (status, body) = match outcome {
        Ok(_) => (axum::http::StatusCode::OK, "You can close this tab."),
        Err(_) => (
            axum::http::StatusCode::BAD_REQUEST,
            "Authorization failed — check the terminal for details.",
        ),
    };
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        body,
    )
}

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

async fn exchange_code(
    endpoint: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    verifier: &str,
) -> anyhow::Result<TokenResponse> {
    let resp = reqwest::Client::new()
        .post(endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ])
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("token endpoint returned {status}: {text}"));
    }
    Ok(serde_json::from_str::<TokenResponse>(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_verifier_and_challenge_match() {
        let (v, c) = generate_pkce();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())),
            c,
            "challenge must be S256(verifier)"
        );
    }

    #[test]
    fn normalize_url_strips_trailing_slash() {
        assert_eq!(normalize_url("http://x/"), "http://x");
        assert_eq!(normalize_url("http://x"), "http://x");
    }

    #[test]
    fn build_authorize_url_encodes_all_params() {
        let u = build_authorize_url(
            "http://as/authorize",
            "osc_abc",
            "http://127.0.0.1:9/callback",
            "chal",
            "state!",
        );
        assert!(u.contains("response_type=code"));
        assert!(u.contains("client_id=osc_abc"));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(u.contains("scope=mcp"));
        assert!(u.contains("state=state%21"));
    }
}
