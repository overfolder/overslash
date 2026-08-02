use crate::template_validation::Issues;
use crate::types::{McpAuth, Runtime, ServiceDefinition};

// --- mcp-runtime congruence -------------------------------------------------

pub(super) fn check_mcp(def: &ServiceDefinition, issues: &mut Issues) {
    match def.runtime {
        Runtime::Http => {
            if def.mcp.is_some() {
                issues.err(
                    "mcp_misplaced",
                    "`mcp` block is only valid when runtime=`mcp`",
                    "mcp",
                );
            }
            for (k, a) in &def.actions {
                if a.mcp_tool.is_some() {
                    issues.err(
                        "mcp_misplaced",
                        "mcp_tool set on an Http-runtime action",
                        format!("actions.{k}.mcp_tool"),
                    );
                }
            }
        }
        Runtime::Mcp => {
            let Some(mcp) = def.mcp.as_ref() else {
                issues.err(
                    "mcp_missing",
                    "runtime=`mcp` but `mcp` block is absent",
                    "mcp",
                );
                return;
            };
            // url is optional — absent means the service instance must supply one.
            // When present, validate scheme (format already checked in extract.rs;
            // this guard catches templates loaded from DB that may have bypassed it).
            if let Some(url) = &mcp.url {
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    issues.err(
                        "mcp_invalid",
                        "mcp.url must begin with http:// or https://",
                        "mcp.url",
                    );
                }
            }
            // secret_name is optional — absent means the service instance must supply one.
            match &mcp.auth {
                McpAuth::None => {}
                McpAuth::Bearer { .. } => {}
                McpAuth::OAuth { provider, .. } => {
                    if provider.trim().is_empty() {
                        issues.err(
                            "mcp_invalid",
                            "mcp.auth.provider must be non-empty when kind is `oauth`",
                            "mcp.auth.provider",
                        );
                    }
                }
            }
            if !def.hosts.is_empty() {
                issues.err(
                    "mcp_misplaced",
                    "`hosts` must be empty for mcp-runtime templates (MCP uses mcp.url)",
                    "hosts",
                );
            }
            if !def.auth.is_empty() {
                issues.err(
                    "mcp_misplaced",
                    "HTTP-style `auth` entries are not used for mcp-runtime templates — put auth under mcp.auth",
                    "auth",
                );
            }
            for (k, a) in &def.actions {
                if !a.method.is_empty() || !a.path.is_empty() {
                    issues.err(
                        "mcp_misplaced",
                        "mcp-runtime actions must not carry HTTP method/path",
                        format!("actions.{k}"),
                    );
                }
                if a.mcp_tool.is_none() {
                    issues.err(
                        "mcp_missing",
                        "mcp-runtime action must carry mcp_tool",
                        format!("actions.{k}.mcp_tool"),
                    );
                }
            }
        }
        // Platform runtime has no mcp block — check_platform_action enforces
        // platform-specific invariants; nothing to do here.
        Runtime::Platform => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::template_validation::core::tests::{minimal_mcp, minimal_valid, run};
    use crate::types::{McpAuth, SecretSource, ServiceAuth, TokenInjection};

    // ── MCP runtime validation ────────────────────────────────────────

    #[test]
    fn mcp_happy_path_valid() {
        let d = minimal_mcp(McpAuth::Bearer {
            secret_name: Some("tok".into()),
        });
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn mcp_bearer_without_secret_name_is_valid() {
        // secret_name absent means the service instance must supply one.
        let d = minimal_mcp(McpAuth::Bearer { secret_name: None });
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn mcp_without_url_is_valid() {
        // url absent means the service instance must supply one.
        let mut d = minimal_mcp(McpAuth::None);
        d.mcp.as_mut().unwrap().url = None;
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn mcp_requires_spec() {
        let mut d = minimal_mcp(McpAuth::None);
        d.mcp = None;
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_missing"));
    }

    #[test]
    fn mcp_rejects_hosts() {
        let mut d = minimal_mcp(McpAuth::None);
        d.hosts = vec!["example.com".into()];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path == "hosts")
        );
    }

    #[test]
    fn mcp_rejects_http_auth() {
        let mut d = minimal_mcp(McpAuth::None);
        d.auth = vec![ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            config_keys: Vec::new(),
            scheme: String::new(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "k".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: None,
            },
            secret_source: SecretSource::Instance,
            optional: false,
        }];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path == "auth")
        );
    }

    #[test]
    fn mcp_rejects_http_action_shape() {
        let mut d = minimal_mcp(McpAuth::None);
        let a = d.actions.get_mut("search").unwrap();
        a.method = "GET".into();
        a.path = "/x".into();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path.starts_with("actions.search"))
        );
    }

    #[test]
    fn mcp_requires_mcp_tool_on_actions() {
        let mut d = minimal_mcp(McpAuth::None);
        d.actions.get_mut("search").unwrap().mcp_tool = None;
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_missing"));
    }

    #[test]
    fn mcp_invalid_url_scheme_rejected() {
        let mut d = minimal_mcp(McpAuth::None);
        d.mcp.as_mut().unwrap().url = Some("mcp.example.com".into());
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_invalid"));
    }

    #[test]
    fn http_runtime_rejects_stray_mcp_block() {
        use crate::types::McpSpec;
        let mut d = minimal_valid();
        d.mcp = Some(McpSpec {
            url: Some("https://x".into()),
            auth: McpAuth::None,
            autodiscover: true,
        });
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path == "mcp")
        );
    }
}
