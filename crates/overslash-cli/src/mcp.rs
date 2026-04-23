use std::path::PathBuf;

/// Resolve the MCP config path from `--config`, `--profile`, or the default.
///
/// - `--config <path>` wins outright.
/// - `--profile foo` reads/writes `~/.config/overslash/mcp.foo.json`.
/// - Default: `~/.config/overslash/mcp.json`.
pub fn resolve_config_path(
    profile: Option<String>,
    config: Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    if let Some(p) = config {
        return Ok(p);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; pass --config explicitly"))?;
    let dir = home.join(".config").join("overslash");
    let file = match profile {
        Some(p) if !p.is_empty() => format!("mcp.{p}.json"),
        _ => "mcp.json".into(),
    };
    Ok(dir.join(file))
}

pub async fn run_stdio(config_path: PathBuf) -> anyhow::Result<()> {
    overslash_mcp::serve_stdio(config_path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_config_path_wins() {
        let p = resolve_config_path(Some("ignored".into()), Some(PathBuf::from("/tmp/foo.json")))
            .unwrap();
        assert_eq!(p, PathBuf::from("/tmp/foo.json"));
    }

    #[test]
    fn default_path_uses_home() {
        // SAFETY: tests are single-threaded per binary by default, but env
        // mutation is still racy across modules — this test just sets a
        // fixed value and reads it back, so the only risk is interleaving
        // with another test that reads HOME, which we don't have.
        unsafe { std::env::set_var("HOME", "/tmp/fake-home") };
        let p = resolve_config_path(None, None).unwrap();
        assert_eq!(
            p,
            PathBuf::from("/tmp/fake-home/.config/overslash/mcp.json")
        );
    }

    #[test]
    fn profile_changes_filename() {
        unsafe { std::env::set_var("HOME", "/tmp/fake-home") };
        let p = resolve_config_path(Some("work".into()), None).unwrap();
        assert_eq!(
            p,
            PathBuf::from("/tmp/fake-home/.config/overslash/mcp.work.json")
        );
    }

    #[test]
    fn empty_profile_is_treated_as_default() {
        unsafe { std::env::set_var("HOME", "/tmp/fake-home") };
        let p = resolve_config_path(Some(String::new()), None).unwrap();
        assert_eq!(
            p,
            PathBuf::from("/tmp/fake-home/.config/overslash/mcp.json")
        );
    }
}
