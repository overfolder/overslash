//! The API's Valkey client, built from `REDIS_*` config (CASA 6.7.1).
//!
//! `REDIS_URL` alone is enough for local dev (`redis://localhost:6380`). In
//! Cloud Run, Memorystore for Valkey runs with IAM auth and in-transit
//! encryption: the URL is `rediss://`, `REDIS_AUTH=gcp-iam` authenticates each
//! connection with the service account's access token, and `REDIS_CA_CERT`
//! (from Secret Manager) is the only trust anchor. `REDIS_PASSWORD` remains for
//! a Valkey with a static AUTH string. The rules live in `overslash_valkey`.
//!
//! Every Redis-backed store (rate limiter, resolver cache, session cache)
//! calls [`client`], so none of them can quietly connect without AUTH or TLS.

use overslash_valkey::{Valkey, Vars};
use redis::RedisResult;

use crate::config::Config;

pub const VARS: Vars = Vars {
    url: "REDIS_URL",
    password: "REDIS_PASSWORD",
    auth: "REDIS_AUTH",
    ca_cert: "REDIS_CA_CERT",
};

/// A client for the configured Valkey, or `None` when `REDIS_URL` is unset.
pub fn client(config: &Config) -> Option<RedisResult<Valkey>> {
    let url = config.redis_url.as_deref()?;
    Some(Valkey::build(
        url,
        &config.redis_auth,
        config.redis_ca_cert.as_deref(),
        &VARS,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_url_means_no_client() {
        assert!(client(&crate::config::tests::empty_test_config()).is_none());
    }

    #[test]
    fn config_auth_and_ca_reach_the_client() {
        let mut config = crate::config::tests::empty_test_config();
        config.redis_url = Some("rediss://10.0.0.3:6379".into());
        config.redis_auth = overslash_valkey::Auth::GcpIam;
        config.redis_ca_cert = Some(include_str!("../../tests/fixtures/valkey-test-ca.pem").into());
        let v = client(&config).unwrap().unwrap();
        assert!(v.uses_gcp_iam());
    }
}
