use std::collections::HashMap;
#[cfg(feature = "yaml")]
use std::path::Path;

use crate::types::ServiceDefinition;

/// In-memory service registry loaded from OpenAPI 3.1 YAML files with
/// `x-overslash-*` vendor extensions. See `crates/overslash-core/src/openapi.rs`
/// for the parse + normalize + compile pipeline.
#[derive(Debug, Clone, Default)]
pub struct ServiceRegistry {
    services: HashMap<String, ServiceDefinition>,
}

impl ServiceRegistry {
    /// Load all .yaml/.yml files from a directory as OpenAPI 3.1 service
    /// templates.
    ///
    /// Each file is parsed via `openapi::parse_yaml`, alias-normalized, and
    /// compiled into a [`ServiceDefinition`]. The compiled definition is then
    /// linted by
    /// [`crate::template_validation::validate_service_definition`]. Files that
    /// fail at any stage are logged as `tracing::error!` and skipped so a
    /// single broken shipped template can't take down the whole process — CI
    /// catches the same cases via `shipped_services_load_clean` below.
    #[cfg(feature = "yaml")]
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

            let mut doc = match crate::openapi::parse_yaml(&content) {
                Ok(d) => d,
                Err(issue) => {
                    tracing::error!(
                        file = %path.display(),
                        code = %issue.code,
                        error = %issue.message,
                        "openapi YAML parse failed; skipping"
                    );
                    continue;
                }
            };

            let ns_issues = crate::openapi::normalize_aliases(&mut doc);
            if !ns_issues.is_empty() {
                tracing::error!(
                    file = %path.display(),
                    issues = ?ns_issues,
                    "alias normalization failed; skipping"
                );
                continue;
            }

            let def = match crate::openapi::compile_service(&doc) {
                Ok((def, _warnings)) => def,
                Err(errors) => {
                    tracing::error!(
                        file = %path.display(),
                        errors = ?errors,
                        "openapi compile failed; skipping"
                    );
                    continue;
                }
            };

            let report = crate::template_validation::validate_service_definition(&def, &[]);
            if !report.valid {
                tracing::error!(
                    file = %path.display(),
                    key = %def.key,
                    errors = ?report.errors,
                    "shipped service template failed validation; skipping"
                );
                continue;
            }

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

#[cfg(all(test, feature = "yaml"))]
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
    fn load_from_dir_parses_openapi_yaml() {
        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "github.yaml",
            r#"
openapi: 3.1.0
info:
  title: GitHub
  key: github
servers:
  - url: https://api.github.com
components:
  securitySchemes:
    token:
      type: apiKey
      in: header
      name: Authorization
      x-overslash-prefix: "Bearer "
      default_secret_name: github_token
paths:
  /user/repos:
    get:
      operationId: list_repos
      summary: List repositories
      risk: read
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
openapi: 3.1.0
info:
  title: GitHub
  key: github
servers:
  - url: https://api.github.com
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(reg.find_by_host("api.github.com").len(), 1);
        assert_eq!(reg.find_by_host("api.stripe.com").len(), 0);
    }

    #[test]
    fn scope_param_parsed_from_openapi() {
        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "github.yaml",
            r#"
openapi: 3.1.0
info:
  title: GitHub
  key: github
servers:
  - url: https://api.github.com
paths:
  /repos/{repo}/pulls:
    post:
      operationId: create_pull_request
      summary: Create a pull request
      risk: write
      scope_param: repo
      parameters:
        - name: repo
          in: path
          required: true
          schema:
            type: string
  /user/repos:
    get:
      operationId: list_repos
      summary: List repositories
      risk: read
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        let gh = reg.get("github").unwrap();
        let create_pr = gh.actions.get("create_pull_request").unwrap();
        assert_eq!(create_pr.scope_param.as_deref(), Some("repo"));
        let list_repos = gh.actions.get("list_repos").unwrap();
        assert_eq!(list_repos.scope_param, None);
    }

    #[test]
    fn search_by_name() {
        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "stripe.yaml",
            r#"
openapi: 3.1.0
info:
  title: Stripe
  key: stripe
servers:
  - url: https://api.stripe.com
paths:
  /v1/charges:
    get:
      operationId: list_charges
      summary: List recent charges
      risk: read
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(reg.search("stripe").len(), 1);
        assert_eq!(reg.search("charges").len(), 1);
        assert_eq!(reg.search("nonexistent").len(), 0);
    }

    #[test]
    fn risk_defaults_from_method_when_omitted() {
        use crate::types::Risk;

        let dir = TempDir::new().unwrap();
        write_yaml(
            dir.path(),
            "test.yaml",
            r#"
openapi: 3.1.0
info:
  title: Test
  key: test
servers:
  - url: https://api.test.com
paths:
  /items:
    get:
      operationId: no_risk
      summary: No risk field
    post:
      operationId: explicit_write
      summary: Explicit write
      risk: write
  /items/{id}:
    delete:
      operationId: explicit_delete
      summary: "Explicit delete of {id}"
      risk: delete
      scope_param: id
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
"#,
        );

        let reg = ServiceRegistry::load_from_dir(dir.path()).unwrap();
        let svc = reg.get("test").unwrap();
        assert_eq!(svc.actions["no_risk"].risk, Risk::Read);
        assert_eq!(svc.actions["explicit_write"].risk, Risk::Write);
        assert_eq!(svc.actions["explicit_delete"].risk, Risk::Delete);
    }

    #[test]
    fn shipped_services_load_clean() {
        // Smoke test: every shipped services/*.yaml must load via the
        // openapi pipeline and pass validation.
        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg = ServiceRegistry::load_from_dir(&services_dir).unwrap();
        assert!(!reg.is_empty(), "no shipped templates loaded");
    }
}
