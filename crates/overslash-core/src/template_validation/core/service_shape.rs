use crate::template_validation::Issues;
use crate::types::{Runtime, ServiceDefinition};

// --- service-level ---------------------------------------------------------

pub(super) fn check_service_shape(def: &ServiceDefinition, issues: &mut Issues) {
    if def.key.is_empty() {
        issues.err("missing_field", "key is required", "key");
    } else if !is_valid_service_key(&def.key) {
        issues.err("invalid_key", "key must match ^[a-z][a-z0-9_-]*$", "key");
    }

    if def.display_name.trim().is_empty() {
        issues.err("missing_field", "display_name is required", "display_name");
    }

    // Platform services have no hosts — they dispatch in-process.
    if def.runtime == Runtime::Platform {
        return;
    }

    for (i, host) in def.hosts.iter().enumerate() {
        let path = format!("hosts[{i}]");
        if host.trim().is_empty() {
            issues.err("invalid_host", "host must be non-empty", path);
        } else if !is_valid_hostname(host) {
            issues.err(
                "invalid_host",
                "host must be a plain hostname (no scheme, no path, no whitespace)",
                path,
            );
        }
    }
}

fn is_valid_service_key(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_valid_hostname(s: &str) -> bool {
    !s.is_empty() && !s.contains("://") && !s.contains('/') && !s.chars().any(|c| c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use crate::template_validation::core::tests::{minimal_valid, run};

    #[test]
    fn invalid_key() {
        let mut d = minimal_valid();
        d.key = "Bad-Key".into();
        let r = run(&d);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.code == "invalid_key"));
    }

    #[test]
    fn missing_display_name() {
        let mut d = minimal_valid();
        d.display_name = "".into();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "missing_field" && e.path == "display_name")
        );
    }

    #[test]
    fn invalid_host() {
        let mut d = minimal_valid();
        d.hosts = vec!["https://api.example.com/foo".into()];
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_host"));
    }
}
