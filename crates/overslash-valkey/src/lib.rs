//! The one place a Valkey client is built from config (CASA 6.7.1).
//!
//! Shared by the API (`REDIS_*`) and oversla-sh (`VALKEY_*`), which differ
//! only in their variable names — see [`Vars`].
//!
//! The URL alone is enough for local dev (`redis://localhost:6380`). In Cloud
//! Run, Memorystore for Valkey has IAM auth and in-transit encryption on, so:
//!
//! - the URL is `rediss://<psc-ip>:<port>`;
//! - `*_AUTH=gcp-iam` makes every new connection present a fresh access token
//!   for the service account (from the metadata server) — there is no stored
//!   password to leak or rotate. See [`gcp_iam`];
//! - `*_CA_CERT` (from Secret Manager) is the PEM bundle of the instance's
//!   server CAs. When set it is the *only* trust anchor (the system store is
//!   not consulted), and the server certificate is still checked against the
//!   URL's host.
//!
//! `*_PASSWORD` is still honoured for a Valkey with a static AUTH string, such
//! as a self-hosted one. It and `*_AUTH` are mutually exclusive.

pub mod gcp_iam;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, ErrorKind, IntoConnectionInfo, RedisError, RedisResult, TlsCertificates};
use rustls::pki_types::{CertificateDer, pem::PemObject};

pub use gcp_iam::GcpIamCredentials;

/// The variable names a binary reads its Valkey settings from. Only used to
/// read them and to name them in errors.
#[derive(Clone, Copy, Debug)]
pub struct Vars {
    pub url: &'static str,
    pub password: &'static str,
    pub auth: &'static str,
    pub ca_cert: &'static str,
}

/// How a client authenticates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Auth {
    /// No AUTH. Local dev and CI.
    #[default]
    None,
    /// A static AUTH string.
    Password(String),
    /// Memorystore IAM auth: a short-lived access token for the runtime's
    /// service account, as user `default`.
    GcpIam,
}

impl Auth {
    /// Parse `*_PASSWORD` and `*_AUTH` from the environment.
    pub fn from_env(vars: &Vars) -> Result<Self, String> {
        Self::parse(
            overslash_env::optional(vars.password),
            overslash_env::optional(vars.auth).as_deref(),
            vars,
        )
    }

    fn parse(password: Option<String>, mode: Option<&str>, vars: &Vars) -> Result<Self, String> {
        match (password, mode) {
            (None, None) => Ok(Self::None),
            (Some(p), None) => Ok(Self::Password(p)),
            (None, Some(m)) if m.eq_ignore_ascii_case("gcp-iam") => Ok(Self::GcpIam),
            (None, Some(m)) => Err(format!(
                "{} must be \"gcp-iam\" or unset, got {m:?}",
                vars.auth
            )),
            (Some(_), Some(_)) => Err(format!(
                "{} and {} are mutually exclusive",
                vars.password, vars.auth
            )),
        }
    }
}

/// A configured client. Cheap to clone.
#[derive(Clone)]
pub struct Valkey {
    client: Client,
    credentials: Option<GcpIamCredentials>,
}

impl Valkey {
    /// Build a client from a URL, an auth mode and an optional CA bundle.
    ///
    /// A CA with a plaintext `redis://` URL is refused rather than ignored:
    /// the operator asked for a verified TLS connection, and silently
    /// connecting in the clear is the failure this module exists to prevent.
    pub fn build(
        url: &str,
        auth: &Auth,
        ca_cert_pem: Option<&str>,
        vars: &Vars,
    ) -> RedisResult<Self> {
        let mut info = url.into_connection_info()?;
        let mut credentials = None;
        match auth {
            Auth::None => {}
            Auth::Password(password) => {
                let settings = info.redis_settings().clone().set_password(password);
                info = info.set_redis_settings(settings);
            }
            Auth::GcpIam => credentials = Some(GcpIamCredentials::from_env()),
        }
        let tls = matches!(info.addr(), redis::ConnectionAddr::TcpTls { .. });
        if tls {
            install_crypto_provider();
        }
        let invalid = |msg: String| {
            RedisError::from((ErrorKind::InvalidClientConfig, "invalid Valkey config", msg))
        };
        let client = match ca_cert_pem {
            Some(_) if !tls => Err(invalid(format!(
                "{} is set but {} is not rediss://",
                vars.ca_cert, vars.url
            ))),
            Some(pem) if !has_certificates(pem) => Err(invalid(format!(
                "{} holds no PEM certificate",
                vars.ca_cert
            ))),
            Some(pem) => Client::build_with_tls(
                info,
                TlsCertificates {
                    client_tls: None,
                    root_cert: Some(pem.as_bytes().to_vec()),
                },
            ),
            None => Client::open(info),
        }?;
        Ok(Self {
            client,
            credentials,
        })
    }

    /// A plain client for a URL, no auth or CA. Tests and local tooling.
    pub fn open(url: &str) -> RedisResult<Self> {
        Ok(Self {
            client: Client::open(url)?,
            credentials: None,
        })
    }

    /// Connect. Every (re)connect the manager makes authenticates with the
    /// configured auth — for IAM, a token that is current at that moment.
    pub async fn connection_manager(&self) -> RedisResult<ConnectionManager> {
        let mut config = ConnectionManagerConfig::new();
        if let Some(credentials) = &self.credentials {
            config = config.set_credentials_provider(credentials.clone());
        }
        self.client.get_connection_manager_with_config(config).await
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn uses_gcp_iam(&self) -> bool {
        self.credentials.is_some()
    }
}

/// `redis` reads the bundle leniently: text with no `BEGIN CERTIFICATE`
/// block becomes an empty root store, which fails every handshake with an
/// opaque error. Reject it at boot instead, where the message can name the var.
fn has_certificates(pem: &str) -> bool {
    let mut certs = CertificateDer::pem_slice_iter(pem.as_bytes()).peekable();
    certs.peek().is_some() && certs.all(|c| c.is_ok())
}

/// `redis` builds its rustls config from the process-default provider. The
/// API links both `ring` and `aws-lc-rs` (via reqwest), so there is no
/// unambiguous default and the first TLS connect would panic. Pin aws-lc-rs;
/// an `Err` only means a provider is already installed, which is fine.
fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Self-signed throwaway CA, used only to prove the PEM path parses.
    const CA_PEM: &str = include_str!("../tests/fixtures/valkey-test-ca.pem");

    const VARS: Vars = Vars {
        url: "REDIS_URL",
        password: "REDIS_PASSWORD",
        auth: "REDIS_AUTH",
        ca_cert: "REDIS_CA_CERT",
    };

    #[test]
    fn plain_url_without_extras_is_unchanged() {
        let v = Valkey::build("redis://localhost:6380", &Auth::None, None, &VARS).unwrap();
        let info = v.client().get_connection_info();
        assert!(matches!(
            info.addr(),
            redis::ConnectionAddr::Tcp(h, 6380) if h == "localhost"
        ));
        assert_eq!(info.redis_settings().password(), None);
        assert!(!v.uses_gcp_iam());
    }

    #[test]
    fn password_is_applied_without_being_in_the_url() {
        let auth = Auth::Password("s3cret".into());
        let v = Valkey::build("rediss://10.0.0.3:6378", &auth, Some(CA_PEM), &VARS).unwrap();
        assert_eq!(
            v.client().get_connection_info().redis_settings().password(),
            Some("s3cret")
        );
    }

    #[test]
    fn gcp_iam_attaches_a_credentials_provider_and_no_password() {
        let v =
            Valkey::build("rediss://10.0.0.3:6379", &Auth::GcpIam, Some(CA_PEM), &VARS).unwrap();
        assert!(v.uses_gcp_iam());
        assert_eq!(
            v.client().get_connection_info().redis_settings().password(),
            None
        );
    }

    #[test]
    fn ca_with_rediss_builds_a_verifying_tls_client() {
        let v = Valkey::build("rediss://10.0.0.3:6378", &Auth::None, Some(CA_PEM), &VARS).unwrap();
        match v.client().get_connection_info().addr() {
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
    fn ca_with_plaintext_url_is_refused_naming_the_vars() {
        let err = Valkey::build("redis://10.0.0.3:6379", &Auth::None, Some(CA_PEM), &VARS)
            .err()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidClientConfig);
        assert!(err.to_string().contains("REDIS_CA_CERT"), "{err}");
    }

    #[test]
    fn malformed_ca_is_an_error_not_an_empty_trust_store() {
        let err = Valkey::build(
            "rediss://10.0.0.3:6378",
            &Auth::None,
            Some("not a pem"),
            &VARS,
        )
        .err()
        .unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidClientConfig);
    }

    #[test]
    fn auth_parses_each_mode() {
        assert_eq!(Auth::parse(None, None, &VARS), Ok(Auth::None));
        assert_eq!(
            Auth::parse(Some("p".into()), None, &VARS),
            Ok(Auth::Password("p".into()))
        );
        assert_eq!(Auth::parse(None, Some("gcp-iam"), &VARS), Ok(Auth::GcpIam));
        assert_eq!(Auth::parse(None, Some("GCP-IAM"), &VARS), Ok(Auth::GcpIam));
    }

    #[test]
    fn auth_rejects_unknown_mode_and_both_at_once() {
        let err = Auth::parse(None, Some("iam"), &VARS).unwrap_err();
        assert!(err.contains("REDIS_AUTH"), "{err}");
        let err = Auth::parse(Some("p".into()), Some("gcp-iam"), &VARS).unwrap_err();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    /// A real handshake against a TLS + AUTH Valkey. Gated because CI's Valkey
    /// is plaintext; this is what proves the crypto-provider pin above. Set
    /// `VALKEY_TLS_TEST_URL`, `VALKEY_TLS_TEST_CA` (a PEM *path*) and either
    /// `VALKEY_TLS_TEST_PASSWORD` or `VALKEY_TLS_TEST_GCP_IAM=1` (with a
    /// metadata server, or `GCE_METADATA_HOST` pointing at one) — see
    /// docs/runbooks/memorystore-valkey.md.
    #[tokio::test]
    async fn live_tls_with_auth_round_trips() {
        let (Some(url), Some(ca_path)) = (
            overslash_env::optional("VALKEY_TLS_TEST_URL"),
            overslash_env::optional("VALKEY_TLS_TEST_CA"),
        ) else {
            eprintln!("skipping: VALKEY_TLS_TEST_* not set");
            return;
        };
        let auth = if overslash_env::flag("VALKEY_TLS_TEST_GCP_IAM") {
            Auth::GcpIam
        } else {
            Auth::Password(overslash_env::optional("VALKEY_TLS_TEST_PASSWORD").expect("password"))
        };
        let ca = std::fs::read_to_string(ca_path).expect("read CA");
        let v = Valkey::build(&url, &auth, Some(&ca), &VARS).expect("client");
        let mut conn = v.connection_manager().await.expect("connect");
        let pong: String = redis::cmd("PING").query_async(&mut conn).await.unwrap();
        assert_eq!(pong, "PONG");

        // The wrong password must not get in.
        let bad =
            Valkey::build(&url, &Auth::Password("wrong".into()), Some(&ca), &VARS).expect("client");
        assert!(bad.connection_manager().await.is_err());

        // Neither must a server whose certificate the pinned CA did not sign.
        let untrusted = Valkey::build(&url, &auth, Some(CA_PEM), &VARS).expect("client");
        assert!(untrusted.connection_manager().await.is_err());
    }
}
