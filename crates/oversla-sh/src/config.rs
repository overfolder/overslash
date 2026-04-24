use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub valkey_url: String,
    pub api_key: String,
    pub base_url: String,
    pub min_ttl_secs: u64,
    pub max_ttl_secs: u64,
    /// If set, `GET /` 302s here. If unset, `GET /` is a 404. Lets
    /// oversla.sh send curious visitors to the marketing site without
    /// baking any brand in the code.
    pub root_redirect_url: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        let valkey_url =
            env::var("VALKEY_URL").map_err(|_| anyhow::anyhow!("VALKEY_URL is required"))?;
        // Trim the key on load so it stays symmetric with the presented
        // token (also trimmed in `auth::ApiKey`). Secret Manager values
        // frequently pick up trailing newlines when populated from shell
        // pipelines; without trimming, a valid key would fail the
        // constant-time length check.
        let api_key = env::var("API_KEY")
            .map_err(|_| anyhow::anyhow!("API_KEY is required"))?
            .trim()
            .to_string();
        if api_key.is_empty() {
            anyhow::bail!("API_KEY must not be empty");
        }
        let base_url = env::var("BASE_URL").map_err(|_| anyhow::anyhow!("BASE_URL is required"))?;
        let base_url = base_url.trim_end_matches('/').to_string();

        let min_ttl_secs = env::var("MIN_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        let max_ttl_secs = env::var("MAX_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(604_800); // 7 days

        if min_ttl_secs == 0 || min_ttl_secs > max_ttl_secs {
            anyhow::bail!(
                "invalid TTL bounds: MIN_TTL_SECS={min_ttl_secs} MAX_TTL_SECS={max_ttl_secs}"
            );
        }

        let root_redirect_url = env::var("ROOT_REDIRECT_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(Self {
            host,
            port,
            valkey_url,
            api_key,
            base_url,
            min_ttl_secs,
            max_ttl_secs,
            root_redirect_url,
        })
    }
}
