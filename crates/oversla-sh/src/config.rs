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
        let api_key = env::var("API_KEY").map_err(|_| anyhow::anyhow!("API_KEY is required"))?;
        if api_key.trim().is_empty() {
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

        Ok(Self {
            host,
            port,
            valkey_url,
            api_key,
            base_url,
            min_ttl_secs,
            max_ttl_secs,
        })
    }
}
