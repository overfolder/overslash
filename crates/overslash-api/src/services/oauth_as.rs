//! Shared helpers for the MCP OAuth Authorization Server:
//!
//! - In-memory authorization-code store (60s TTL, single-use).
//! - PKCE S256 verification.
//! - Refresh-token random generation and hashing.
//!
//! The code store is deliberately in-process for v1. Authorization codes are
//! one-shot, 60s TTL, and horizontal replication is not yet a goal (see
//! `STATUS.md` + `TECH_DEBT.md`). The store lives behind a simple facade so a
//! Redis-backed implementation can drop in when the time comes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// One-shot authorization code produced by `GET /oauth/authorize` and
/// redeemed at `POST /oauth/token`. The `issued_at` Instant is used for TTL
/// enforcement; the TTL is 60 seconds per RFC 6749 §4.1.2 recommendations.
#[derive(Debug, Clone)]
pub struct AuthCodeRecord {
    pub client_id: String,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub issued_at: Instant,
}

pub const AUTH_CODE_TTL: Duration = Duration::from_secs(60);
pub const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600; // 30 days
pub const ACCESS_TOKEN_TTL_SECS: i64 = 3600; // 1 hour

#[derive(Default, Clone)]
pub struct AuthCodeStore {
    inner: Arc<Mutex<std::collections::HashMap<String, AuthCodeRecord>>>,
}

impl AuthCodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, code: String, record: AuthCodeRecord) {
        let mut map = self.inner.lock().expect("auth code store poisoned");
        Self::prune_locked(&mut map);
        map.insert(code, record);
    }

    /// Consume a code atomically — succeeds at most once. Returns `None`
    /// if the code is unknown or expired.
    pub fn take(&self, code: &str) -> Option<AuthCodeRecord> {
        let mut map = self.inner.lock().expect("auth code store poisoned");
        let rec = map.remove(code)?;
        if rec.issued_at.elapsed() > AUTH_CODE_TTL {
            return None;
        }
        Some(rec)
    }

    fn prune_locked(map: &mut std::collections::HashMap<String, AuthCodeRecord>) {
        map.retain(|_, r| r.issued_at.elapsed() <= AUTH_CODE_TTL);
    }
}

/// Compute the S256 PKCE challenge from a verifier per RFC 7636:
/// `BASE64URL-NOPAD(SHA256(ASCII(verifier)))`.
pub fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Generate a single-use authorization code (URL-safe, 32 bytes of entropy).
pub fn generate_auth_code() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Generate a refresh token (raw). Return raw + sha256 hash — the hash is
/// what's persisted in `mcp_refresh_tokens`, and the raw value is only
/// handed to the client once.
pub fn generate_refresh_token() -> (String, Vec<u8>) {
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    let raw = URL_SAFE_NO_PAD.encode(buf);
    let hash = Sha256::digest(raw.as_bytes()).to_vec();
    (raw, hash)
}

/// Hash an arbitrary token string for lookup in the persisted table.
pub fn hash_refresh_token(raw: &str) -> Vec<u8> {
    Sha256::digest(raw.as_bytes()).to_vec()
}

/// Generate a DCR client_id. Shape: `osc_` + 32 URL-safe chars.
pub fn generate_client_id() -> String {
    let mut buf = [0u8; 24];
    rand::rng().fill(&mut buf);
    format!("osc_{}", URL_SAFE_NO_PAD.encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256(verifier), expected);
    }

    #[test]
    fn auth_code_take_is_single_use() {
        let store = AuthCodeStore::new();
        store.insert(
            "abc".into(),
            AuthCodeRecord {
                client_id: "c".into(),
                identity_id: Uuid::nil(),
                org_id: Uuid::nil(),
                email: "e".into(),
                redirect_uri: "r".into(),
                code_challenge: "x".into(),
                issued_at: Instant::now(),
            },
        );
        assert!(store.take("abc").is_some());
        assert!(store.take("abc").is_none());
    }
}
