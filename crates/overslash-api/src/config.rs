use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub secrets_encryption_key: String,
    pub approval_expiry_secs: u64,
    pub services_dir: String,
    pub google_auth_client_id: Option<String>,
    pub google_auth_client_secret: Option<String>,
    pub public_url: String,
    pub dev_auth_enabled: bool,
    pub max_response_body_bytes: usize,
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
            services_dir: env::var("SERVICES_DIR").unwrap_or_else(|_| "services".into()),
            google_auth_client_id: env::var("GOOGLE_AUTH_CLIENT_ID").ok(),
            google_auth_client_secret: env::var("GOOGLE_AUTH_CLIENT_SECRET").ok(),
            public_url: env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into()),
            dev_auth_enabled: env::var("DEV_AUTH").is_ok(),
            max_response_body_bytes: env::var("MAX_RESPONSE_BODY_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5_242_880), // 5 MB
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
