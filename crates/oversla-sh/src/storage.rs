use redis::{
    AsyncCommands, Client, ErrorKind, IntoConnectionInfo, RedisError, TlsCertificates,
    aio::ConnectionManager,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};

use crate::error::{AppError, Result};
use crate::slug;

const KEY_PREFIX: &str = "sh:";
const MAX_COLLISION_RETRIES: u32 = 3;
const SLUG_LEN: usize = 10;

/// Thin wrapper over a Valkey `ConnectionManager`. `Clone` is cheap —
/// `ConnectionManager` is internally `Arc`-ed.
#[derive(Clone)]
pub struct Storage {
    conn: ConnectionManager,
}

impl Storage {
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_with(url, None, None).await
    }

    /// Connect with Memorystore AUTH and a pinned server CA (CASA 6.7.1).
    /// See `client` for how the three values combine.
    pub async fn connect_with(
        url: &str,
        password: Option<&str>,
        ca_cert_pem: Option<&str>,
    ) -> Result<Self> {
        let conn = client(url, password, ca_cert_pem)?
            .get_connection_manager()
            .await?;
        Ok(Self { conn })
    }

    /// Probe the backend. Used by `/ready`.
    pub async fn ping(&self) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(())
    }

    /// Generate a fresh slug and store the URL under it with the given TTL.
    /// Uses `SET ... NX` so a collision returns without overwriting, and we
    /// retry with a fresh slug. At 10 chars of base62 the collision
    /// probability is negligible, but we still bound the retries.
    pub async fn put(&self, url: &str, ttl_seconds: u64) -> Result<String> {
        let mut conn = self.conn.clone();
        for _ in 0..MAX_COLLISION_RETRIES {
            let slug = slug::generate(SLUG_LEN);
            let key = format!("{KEY_PREFIX}{slug}");
            let set: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg(url)
                .arg("NX")
                .arg("EX")
                .arg(ttl_seconds)
                .query_async(&mut conn)
                .await?;
            if set.as_deref() == Some("OK") {
                return Ok(slug);
            }
        }
        Err(AppError::SlugCollision(MAX_COLLISION_RETRIES))
    }

    /// Look up a slug's target URL. Returns `None` if missing/expired.
    pub async fn get(&self, slug: &str) -> Result<Option<String>> {
        if !slug::is_valid(slug) {
            return Ok(None);
        }
        let mut conn = self.conn.clone();
        let key = format!("{KEY_PREFIX}{slug}");
        let value: Option<String> = conn.get(&key).await?;
        Ok(value)
    }
}

/// Mirror of `overslash_api::services::valkey::build` — this crate stays free
/// of an API dependency, so the twenty lines are repeated rather than shared.
///
/// `password` is the AUTH string, kept out of `VALKEY_URL` so the URL is not a
/// secret. `ca_cert_pem`, when set, becomes the only trust anchor and requires
/// a `rediss://` URL; the server certificate is still checked against the
/// URL's host.
fn client(
    url: &str,
    password: Option<&str>,
    ca_cert_pem: Option<&str>,
) -> std::result::Result<Client, RedisError> {
    let mut info = url.into_connection_info()?;
    if let Some(password) = password {
        let settings = info.redis_settings().clone().set_password(password);
        info = info.set_redis_settings(settings);
    }
    let tls = matches!(info.addr(), redis::ConnectionAddr::TcpTls { .. });
    if tls {
        // No crypto provider is otherwise linked here, and `redis` builds its
        // rustls config from the process default. Already-installed is fine.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    let invalid = |msg: &'static str| RedisError::from((ErrorKind::InvalidClientConfig, msg));
    match ca_cert_pem {
        Some(_) if !tls => Err(invalid(
            "VALKEY_CA_CERT is set but VALKEY_URL is not rediss://",
        )),
        Some(pem) if !has_certificates(pem) => {
            Err(invalid("VALKEY_CA_CERT holds no PEM certificate"))
        }
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

fn has_certificates(pem: &str) -> bool {
    let mut certs = CertificateDer::pem_slice_iter(pem.as_bytes()).peekable();
    certs.peek().is_some() && certs.all(|c| c.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA_PEM: &str = include_str!("../tests/fixtures/valkey-test-ca.pem");

    #[test]
    fn plain_url_stays_plain() {
        let c = client("redis://localhost:6380", None, None).unwrap();
        assert!(matches!(
            c.get_connection_info().addr(),
            redis::ConnectionAddr::Tcp(..)
        ));
    }

    #[test]
    fn auth_and_ca_give_a_verifying_tls_client() {
        let c = client("rediss://10.0.0.3:6378", Some("s3cret"), Some(CA_PEM)).unwrap();
        let info = c.get_connection_info();
        assert_eq!(info.redis_settings().password(), Some("s3cret"));
        assert!(matches!(
            info.addr(),
            redis::ConnectionAddr::TcpTls {
                insecure: false,
                port: 6378,
                ..
            }
        ));
    }

    #[test]
    fn ca_with_plaintext_url_is_refused() {
        let err = client("redis://10.0.0.3:6379", None, Some(CA_PEM)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidClientConfig);
    }

    #[test]
    fn a_bundle_without_certificates_is_refused() {
        let err = client("rediss://10.0.0.3:6378", None, Some("garbage")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidClientConfig);
    }
}
