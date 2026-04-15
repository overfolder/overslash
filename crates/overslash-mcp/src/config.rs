use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Base URL of the Overslash API (e.g. `https://acme.overslash.dev`).
    pub server_url: String,
    /// Agent API key used for `overslash_search`, `overslash_execute`, `overslash_auth`.
    pub agent_key: String,
    /// User access token used for `overslash_approve` (and any other user-scoped op).
    pub user_token: String,
    /// Refresh token for the user access token. Optional but strongly recommended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_refresh_token: Option<String>,
}

impl McpConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        write_secret_file(path, &bytes)?;
        Ok(())
    }
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::{fs::OpenOptions, io::Write};
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("overslash-mcp-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("mcp.json")
    }

    #[test]
    fn save_then_load_roundtrip() {
        let path = tmp_path("roundtrip");
        let cfg = McpConfig {
            server_url: "https://acme.overslash.dev".into(),
            agent_key: "ovs_acme_agent_xyz".into(),
            user_token: "ovs_user_alice_abc".into(),
            user_refresh_token: Some("ovs_refresh_xyz".into()),
        };
        cfg.save(&path).unwrap();
        let loaded = McpConfig::load(&path).unwrap();
        assert_eq!(loaded.server_url, cfg.server_url);
        assert_eq!(loaded.agent_key, cfg.agent_key);
        assert_eq!(loaded.user_token, cfg.user_token);
        assert_eq!(loaded.user_refresh_token, cfg.user_refresh_token);
    }

    #[cfg(unix)]
    #[test]
    fn save_uses_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("perms");
        let cfg = McpConfig {
            server_url: "https://x".into(),
            agent_key: "k".into(),
            user_token: "t".into(),
            user_refresh_token: None,
        };
        cfg.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be mode 0600, got {mode:o}");
    }

    #[test]
    fn refresh_token_is_optional() {
        let path = tmp_path("optional");
        let cfg = McpConfig {
            server_url: "https://x".into(),
            agent_key: "k".into(),
            user_token: "t".into(),
            user_refresh_token: None,
        };
        cfg.save(&path).unwrap();
        // The on-disk JSON should omit the field rather than write `null`.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("user_refresh_token"),
            "unexpected serialized refresh token in: {raw}"
        );
        let loaded = McpConfig::load(&path).unwrap();
        assert!(loaded.user_refresh_token.is_none());
    }
}
