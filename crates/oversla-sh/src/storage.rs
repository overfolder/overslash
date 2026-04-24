use redis::{AsyncCommands, aio::ConnectionManager};

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
        let client = redis::Client::open(url)?;
        let conn = client.get_connection_manager().await?;
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
