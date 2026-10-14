//! The one place a Valkey client is built from config (CASA 6.7.1).
//!
//! `REDIS_URL` alone is enough for local dev (`redis://localhost:6380`). In
//! Cloud Run the Memorystore instance has AUTH and in-transit encryption on,
//! so the URL is `rediss://<ip>:6378` and two more values arrive from Secret
//! Manager via `secret_key_ref`, never as plaintext env:
//!
//! - `REDIS_PASSWORD` — the instance AUTH string. Kept out of the URL so the
//!   URL itself stays a non-secret, plan-visible value.
//! - `REDIS_CA_CERT` — PEM bundle of the instance's server CAs. When set it is
//!   the *only* trust anchor (the system store is not consulted), and the
//!   server certificate is still checked against the URL's host.
//!
//! Every Redis-backed store (rate limiter, resolver cache, session cache)
//! calls [`client`], so none of them can quietly connect without AUTH or TLS.

use redis::{Client, ErrorKind, IntoConnectionInfo, RedisError, RedisResult, TlsCertificates};
use rustls::pki_types::{CertificateDer, pem::PemObject};

use crate::config::Config;

/// A client for the configured Valkey, or `None` when `REDIS_URL` is unset.
pub fn client(config: &Config) -> Option<RedisResult<Client>> {
    let url = config.redis_url.as_deref()?;
    Some(build(
        url,
        config.redis_password.as_deref(),
        config.redis_ca_cert.as_deref(),
    ))
}

/// Build a client from a URL plus an optional AUTH string and CA bundle.
///
/// A CA with a plaintext `redis://` URL is refused rather than ignored: the
/// operator asked for a verified TLS connection, and silently connecting in
/// the clear is the failure this module exists to prevent.
pub fn build(url: &str, password: Option<&str>, ca_cert_pem: Option<&str>) -> RedisResult<Client> {
    let mut info = url.into_connection_info()?;
    if let Some(password) = password {
        let settings = info.redis_settings().clone().set_password(password);
        info = info.set_redis_settings(settings);
    }
    let tls = matches!(info.addr(), redis::ConnectionAddr::TcpTls { .. });
    if tls {
        install_crypto_provider();
    }
    match ca_cert_pem {
        Some(_) if !tls => Err(RedisError::from((
            ErrorKind::InvalidClientConfig,
            "REDIS_CA_CERT is set but REDIS_URL is not rediss://",
        ))),
        Some(pem) if !has_certificates(pem) => Err(RedisError::from((
            ErrorKind::InvalidClientConfig,
            "REDIS_CA_CERT holds no PEM certificate",
        ))),
        Some(pem) => Client::build_with_tls(
            info,
            TlsCertificates {
                client_tls: None,
                root_cert: Some(pem.as_bytes().to_vec()),
            },
        ),
        None => Client::open(info),
    }
}

/// `redis` reads the bundle leniently: text with no `BEGIN CERTIFICATE`
/// block becomes an empty root store, which fails every handshake with an
/// opaque error. Reject it at boot instead, where the message can name the var.
fn has_certificates(pem: &str) -> bool {
    let mut certs = CertificateDer::pem_slice_iter(pem.as_bytes()).peekable();
    certs.peek().is_some() && certs.all(|c| c.is_ok())
}

/// `redis` builds its rustls config from the process-default provider, and
/// this binary links both `ring` and `aws-lc-rs` (via reqwest), so there is no
/// unambiguous default and the first TLS connect would panic. Pin aws-lc-rs;
/// an `Err` only means a provider is already installed, which is fine.
fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Self-signed throwaway CA, used only to prove the PEM path parses.
    const CA_PEM: &str = include_str!("../../tests/fixtures/valkey-test-ca.pem");

    #[test]
    fn plain_url_without_extras_is_unchanged() {
        let c = build("redis://localhost:6380", None, None).unwrap();
        let info = c.get_connection_info();
        assert!(matches!(
            info.addr(),
            redis::ConnectionAddr::Tcp(h, 6380) if h == "localhost"
        ));
        assert_eq!(info.redis_settings().password(), None);
    }

    #[test]
    fn password_is_applied_without_being_in_the_url() {
        let c = build("rediss://10.0.0.3:6378", Some("s3cret"), Some(CA_PEM)).unwrap();
        assert_eq!(
            c.get_connection_info().redis_settings().password(),
            Some("s3cret")
        );
    }

    #[test]
    fn ca_with_rediss_builds_a_verifying_tls_client() {
        let c = build("rediss://10.0.0.3:6378", None, Some(CA_PEM)).unwrap();
        match c.get_connection_info().addr() {
            redis::ConnectionAddr::TcpTls {
                host,
                port,
                insecure,
                ..
            } => {
                assert_eq!((host.as_str(), *port), ("10.0.0.3", 6378));
                assert!(!insecure, "server certificate must be verified");
            }
            other => panic!("expected TLS, got {other:?}"),
        }
    }

    #[test]
    fn ca_with_plaintext_url_is_refused() {
        let err = build("redis://10.0.0.3:6379", None, Some(CA_PEM)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidClientConfig);
    }

    #[test]
    fn malformed_ca_is_an_error_not_an_empty_trust_store() {
        let err = build("rediss://10.0.0.3:6378", None, Some("not a pem")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidClientConfig);
    }

    #[test]
    fn unset_url_means_no_client() {
        assert!(client(&crate::config::tests::empty_test_config()).is_none());
    }

    /// A real handshake against a TLS + AUTH Valkey. Gated because CI's Valkey
    /// is plaintext; this is what proves the crypto-provider pin above (this
    /// binary links two providers, so without it the connect panics). Set
    /// `VALKEY_TLS_TEST_URL`, `VALKEY_TLS_TEST_PASSWORD` and
    /// `VALKEY_TLS_TEST_CA` (a PEM *path*) — see docs/runbooks/memorystore-auth-tls.md.
    #[tokio::test]
    async fn live_tls_with_auth_round_trips() {
        let (Some(url), Some(password), Some(ca_path)) = (
            overslash_env::optional("VALKEY_TLS_TEST_URL"),
            overslash_env::optional("VALKEY_TLS_TEST_PASSWORD"),
            overslash_env::optional("VALKEY_TLS_TEST_CA"),
        ) else {
            eprintln!("skipping: VALKEY_TLS_TEST_* not set");
            return;
        };
        let ca = std::fs::read_to_string(ca_path).expect("read CA");
        let client = build(&url, Some(&password), Some(&ca)).expect("client");
        let mut conn = client.get_connection_manager().await.expect("connect");
        let pong: String = redis::cmd("PING").query_async(&mut conn).await.unwrap();
        assert_eq!(pong, "PONG");

        // The wrong password must not get in.
        let bad = build(&url, Some("wrong"), Some(&ca)).expect("client");
        assert!(bad.get_connection_manager().await.is_err());

        // Neither must a server whose certificate the pinned CA did not sign.
        let foreign = include_str!("../../tests/fixtures/valkey-test-ca.pem");
        let untrusted = build(&url, Some(&password), Some(foreign)).expect("client");
        assert!(untrusted.get_connection_manager().await.is_err());
    }
}
