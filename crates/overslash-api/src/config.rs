use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub secrets_encryption_key: String,
    pub signing_key: String,
    pub approval_expiry_secs: u64,
    pub services_dir: String,
    pub google_auth_client_id: Option<String>,
    pub google_auth_client_secret: Option<String>,
    pub github_auth_client_id: Option<String>,
    pub github_auth_client_secret: Option<String>,
    pub public_url: String,
    pub dev_auth_enabled: bool,
    pub max_response_body_bytes: usize,
    pub dashboard_url: String,
    pub redis_url: Option<String>,
    pub default_rate_limit: u32,
    pub default_rate_window_secs: u32,
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
            signing_key: env::var("SIGNING_KEY").expect("SIGNING_KEY is required"),
            approval_expiry_secs: env::var("APPROVAL_EXPIRY_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800),
            services_dir: env::var("SERVICES_DIR").unwrap_or_else(|_| "services".into()),
            google_auth_client_id: env::var("GOOGLE_AUTH_CLIENT_ID").ok(),
            google_auth_client_secret: env::var("GOOGLE_AUTH_CLIENT_SECRET").ok(),
            github_auth_client_id: env::var("GITHUB_AUTH_CLIENT_ID").ok(),
            github_auth_client_secret: env::var("GITHUB_AUTH_CLIENT_SECRET").ok(),
            public_url: env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into()),
            dev_auth_enabled: env::var("DEV_AUTH").is_ok(),
            max_response_body_bytes: env::var("MAX_RESPONSE_BODY_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5_242_880), // 5 MB
            dashboard_url: env::var("DASHBOARD_URL").unwrap_or_else(|_| "/".into()),
            redis_url: env::var("REDIS_URL").ok(),
            default_rate_limit: env::var("DEFAULT_RATE_LIMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            default_rate_window_secs: env::var("DEFAULT_RATE_WINDOW_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
        }
    }

    /// Check for required env vars and return list of missing ones.
    pub fn validate_env() -> Vec<&'static str> {
        let required = ["DATABASE_URL", "SECRETS_ENCRYPTION_KEY", "SIGNING_KEY"];
        required
            .iter()
            .filter(|k| env::var(k).is_err())
            .copied()
            .collect()
    }

    /// Returns env-var-based auth credentials for a given provider key, if configured.
    /// Env vars take precedence over DB-stored IdP configs.
    pub fn env_auth_credentials(&self, provider_key: &str) -> Option<(String, String)> {
        match provider_key {
            "google" => self
                .google_auth_client_id
                .as_ref()
                .zip(self.google_auth_client_secret.as_ref())
                .map(|(a, b)| (a.clone(), b.clone())),
            "github" => self
                .github_auth_client_id
                .as_ref()
                .zip(self.github_auth_client_secret.as_ref())
                .map(|(a, b)| (a.clone(), b.clone())),
            _ => None,
        }
    }
}
