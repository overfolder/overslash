use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub secrets_encryption_key: String,
    pub approval_expiry_secs: u64,
}

impl Config {
    /// Load config from environment variables.
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL is required"),
            secrets_encryption_key: env::var("SECRETS_ENCRYPTION_KEY")
                .expect("SECRETS_ENCRYPTION_KEY is required"),
            approval_expiry_secs: env::var("APPROVAL_EXPIRY_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800),
        }
    }

    /// Check for required env vars and return list of missing ones.
    pub fn validate_env() -> Vec<&'static str> {
        let required = ["DATABASE_URL", "SECRETS_ENCRYPTION_KEY"];
        required
            .iter()
            .filter(|k| env::var(k).is_err())
            .copied()
            .collect()
    }
}
