use std::collections::HashMap;
use std::path::Path;

use crate::types::ServiceDefinition;

/// In-memory service registry loaded from YAML files.
#[derive(Debug, Clone, Default)]
pub struct ServiceRegistry {
    services: HashMap<String, ServiceDefinition>,
}

impl ServiceRegistry {
    /// Load all .yaml/.yml files from a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self, RegistryError> {
        let mut services = HashMap::new();

        if !dir.exists() {
            return Ok(Self { services });
        }

        let entries = std::fs::read_dir(dir).map_err(|e| RegistryError::Io(e.to_string()))?;

        for entry in entries {
            let entry = entry.map_err(|e| RegistryError::Io(e.to_string()))?;
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }

            let content =
                std::fs::read_to_string(&path).map_err(|e| RegistryError::Io(e.to_string()))?;
            let def: ServiceDefinition =
                serde_yaml::from_str(&content).map_err(|e| RegistryError::Parse {
                    file: path.display().to_string(),
                    error: e.to_string(),
                })?;

            services.insert(def.key.clone(), def);
        }

        Ok(Self { services })
    }

    /// Get a service definition by key.
    pub fn get(&self, key: &str) -> Option<&ServiceDefinition> {
        self.services.get(key)
    }

    /// Find services whose hosts match a given hostname.
    pub fn find_by_host(&self, host: &str) -> Vec<&ServiceDefinition> {
        self.services
            .values()
            .filter(|s| s.hosts.iter().any(|h| h == host))
            .collect()
    }

    /// List all service keys.
    pub fn keys(&self) -> Vec<&str> {
        self.services.keys().map(String::as_str).collect()
    }

    /// List all services.
    pub fn all(&self) -> Vec<&ServiceDefinition> {
        self.services.values().collect()
    }

    /// Search services by query (simple substring match on key, display_name, action descriptions).
    pub fn search(&self, query: &str) -> Vec<&ServiceDefinition> {
        let q = query.to_lowercase();
        self.services
            .values()
            .filter(|s| {
                s.key.to_lowercase().contains(&q)
                    || s.display_name.to_lowercase().contains(&q)
                    || s.actions
                        .values()
                        .any(|a| a.description.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Add or replace a service definition (for org-level overrides).
    pub fn insert(&mut self, def: ServiceDefinition) {
        self.services.insert(def.key.clone(), def);
    }

    pub fn len(&self) -> usize {
        self.services.len()
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error in {file}: {error}")]
    Parse { file: String, error: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_yaml(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn load_from_dir_parses_yaml() {
        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "github.yaml",
            r#"
key: github
display_name: GitHub
hosts: [api.github.com]
auth:
  - type: api_key
    default_secret_name: github_token
    injection:
      as: header
      header_name: Authorization
      prefix: "Bearer "
actions:
  list_repos:
    method: GET
    path: /user/repos
    description: List repositories
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(reg.len(), 1);
        let gh = reg.get("github").unwrap();
        assert_eq!(gh.display_name, "GitHub");
        assert_eq!(gh.hosts, vec!["api.github.com"]);
        assert!(gh.actions.contains_key("list_repos"));
    }

    #[test]
    fn find_by_host() {
        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "github.yaml",
            r#"
key: github
display_name: GitHub
hosts: [api.github.com]
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(reg.find_by_host("api.github.com").len(), 1);
        assert_eq!(reg.find_by_host("api.stripe.com").len(), 0);
    }

    #[test]
    fn search_by_name() {
        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "stripe.yaml",
            r#"
key: stripe
display_name: Stripe
hosts: [api.stripe.com]
actions:
  list_charges:
    method: GET
    path: /v1/charges
    description: List recent charges
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(reg.search("stripe").len(), 1);
        assert_eq!(reg.search("charges").len(), 1);
        assert_eq!(reg.search("nonexistent").len(), 0);
    }

    #[test]
    fn risk_defaults_to_read_when_omitted() {
        use crate::types::Risk;

        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "test.yaml",
            r#"
key: test
display_name: Test
hosts: [api.test.com]
actions:
  no_risk:
    method: GET
    path: /items
    description: No risk field
  explicit_write:
    method: POST
    path: /items
    description: Explicit write
    risk: write
  explicit_delete:
    method: DELETE
    path: /items/{id}
    description: Explicit delete
    risk: delete
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        let svc = reg.get("test").unwrap();
        assert_eq!(svc.actions["no_risk"].risk, Risk::Read);
        assert_eq!(svc.actions["explicit_write"].risk, Risk::Write);
        assert_eq!(svc.actions["explicit_delete"].risk, Risk::Delete);
    }
}
