use std::path::Path;

use serde::{Deserialize, Serialize};

/// Single-credential MCP shim config. Written by `overslash mcp login`,
/// read by `overslash mcp` (the stdio↔HTTP pump). Lives at
/// `~/.config/overslash/mcp.json` with mode 0600 on unix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Base URL of the Overslash API (e.g. `https://acme.overslash.dev`).
    pub server_url: String,
    /// Bearer token presented on every `POST /mcp` frame. Minted by
    /// `/oauth/token` during `overslash mcp login`, or an `osk_…` agent key
    /// pasted in directly for agent-mode use.
    pub token: String,
    /// Refresh token paired with `token`. Only set for OAuth-minted tokens;
    /// absent for static `osk_` keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// DCR client_id, persisted after the first `mcp login` so subsequent
    /// logins reuse the registration instead of creating a duplicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
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
            token: "ovs_access_xyz".into(),
            refresh_token: Some("ovs_refresh_xyz".into()),
            client_id: Some("osc_abc".into()),
        };
        cfg.save(&path).unwrap();
        let loaded = McpConfig::load(&path).unwrap();
        assert_eq!(loaded.server_url, cfg.server_url);
        assert_eq!(loaded.token, cfg.token);
        assert_eq!(loaded.refresh_token, cfg.refresh_token);
        assert_eq!(loaded.client_id, cfg.client_id);
    }

    #[cfg(unix)]
    #[test]
    fn save_uses_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("perms");
        let cfg = McpConfig {
            server_url: "https://x".into(),
            token: "t".into(),
            refresh_token: None,
            client_id: None,
        };
        cfg.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be mode 0600, got {mode:o}");
    }

    #[test]
    fn optional_fields_are_skipped_when_none() {
        let path = tmp_path("optional");
        let cfg = McpConfig {
            server_url: "https://x".into(),
            token: "t".into(),
            refresh_token: None,
            client_id: None,
        };
        cfg.save(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("refresh_token"), "unexpected: {raw}");
        assert!(!raw.contains("client_id"), "unexpected: {raw}");
    }
}
