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
        let host = overslash_env::or_default("HOST", "0.0.0.0");
        let port = overslash_env::parse_opt("PORT").unwrap_or(8080);
        let valkey_url = overslash_env::required("VALKEY_URL")?;
        // `overslash_env` trims, which keeps the stored key symmetric with
        // the presented token (also trimmed in `auth::ApiKey`). Secret Manager
        // values frequently pick up trailing newlines when populated from
        // shell pipelines; untrimmed, a valid key fails the constant-time
        // length check.
        let api_key = overslash_env::required("API_KEY")?;
        let base_url = overslash_env::required("BASE_URL")?
            .trim_end_matches('/')
            .to_string();

        let min_ttl_secs = overslash_env::parse_opt("MIN_TTL_SECS").unwrap_or(60);
        let max_ttl_secs = overslash_env::parse_opt("MAX_TTL_SECS").unwrap_or(604_800); // 7 days

        if min_ttl_secs == 0 || min_ttl_secs > max_ttl_secs {
            anyhow::bail!(
                "invalid TTL bounds: MIN_TTL_SECS={min_ttl_secs} MAX_TTL_SECS={max_ttl_secs}"
            );
        }

        let root_redirect_url = overslash_env::optional("ROOT_REDIRECT_URL");

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
