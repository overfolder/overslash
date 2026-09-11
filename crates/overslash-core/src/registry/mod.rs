use crate::service_icon::ServiceIcon;
use std::collections::HashMap;
#[cfg(feature = "yaml")]
use std::path::Path;

use crate::template_vars::{self, Vars};
use crate::types::{Runtime, ServiceDefinition};

/// In-memory service registry loaded from OpenAPI 3.1 YAML files with
/// `x-overslash-*` vendor extensions. See `crates/overslash-core/src/openapi.rs`
/// for the parse + normalize + compile pipeline.
///
/// Carries the deployment's [`Vars`] so the org/user-template resolve path can
/// expand the same `${VAR}` references the shipped templates use without a
/// second source of truth for them.
#[derive(Debug, Clone, Default)]
pub struct ServiceRegistry {
    services: HashMap<String, ServiceDefinition>,
    vars: Vars,
}

/// Key of the synthetic raw-HTTP pseudo-service.
///
/// The one template for which `hosts: []` means "unbound — the caller names the
/// target on every call". Every other host-less template is one whose endpoint
/// simply isn't known yet (`servers: []`, or an unset `${VAR?}`), and must not
/// be treated as an escape hatch. Named so the two places that care can't drift
/// apart on a string literal.
pub const HTTP_PSEUDO_SERVICE: &str = "http";

/// The synthetic `http` pseudo-service template — Mode A's resolution path
/// runs through the standard Service+HTTP-verb code as `service: "http"`.
/// `hosts: []` is the signal that the caller supplies the full URL (no
/// host binding); `auth: []` means there's no template-bound credential
/// (only per-call `secrets[]`).
fn http_pseudo_service() -> ServiceDefinition {
    ServiceDefinition {
        key: HTTP_PSEUDO_SERVICE.to_string(),
        display_name: "Raw HTTP".to_string(),
        description: Some(
            "Raw HTTP — caller supplies the full URL. Per-call secrets injection only.".to_string(),
        ),
        hosts: Vec::new(),
        category: Some("Platform".to_string()),
        hidden: false,
        // Set explicitly rather than left to the implicit rule: this
        // definition is built here in Rust and never passes through
        // `compile_service`, which is where `implicit_for_key` runs. A globe
        // rather than a vendor mark — Mode A stands for "any URL you supply".
        icon: ServiceIcon::implicit_for_key(HTTP_PSEUDO_SERVICE),
        auth: Vec::new(),
        secrets: Vec::new(),
        config: Vec::new(),
        actions: HashMap::new(),
        // No upstream of its own to be slow — Mode A's timeout comes entirely
        // from the caller, the org, or the deployment default.
        default_timeout_ms: None,
        runtime: Runtime::Http,
        mcp: None,
        instance_defaults: None,
    }
}

impl ServiceRegistry {
    /// Load all .yaml/.yml files from a directory as OpenAPI 3.1 service
    /// templates.
    ///
    /// Each file is parsed via `openapi::parse_yaml`, alias-normalized,
    /// variable-expanded against `vars`, and compiled into a
    /// [`ServiceDefinition`]. The compiled definition is then linted by
    /// [`crate::template_validation::validate_service_definition`]. Files that
    /// fail at any stage are logged as `tracing::error!` and skipped so a
    /// single broken shipped template can't take down the whole process — CI
    /// catches the same cases via `shipped_services_load_clean` below.
    ///
    /// The extension lint ([`crate::openapi::lint_extensions`]) is the one check
    /// that reports without skipping: its findings are `tracing::warn!` and the
    /// template still loads, because a key nothing reads is a smaller problem
    /// than an absent service. `shipped_services_lint_clean` is where that
    /// leniency is paid for.
    ///
    /// `vars` is normally [`Vars::from_env`]; tests pass an explicit set rather
    /// than mutating the process environment, which races across the suite.
    #[cfg(feature = "yaml")]
    pub fn load_from_dir(dir: &Path, vars: Vars) -> Result<Self, RegistryError> {
        let mut services = HashMap::new();

        if !dir.exists() {
            return Ok(Self { services, vars });
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

            // Extension lint findings are logged and the template still loads.
            // Making them fatal here would mean a stray key *removes a service*,
            // which is strictly worse than the ignored field the lint exists to
            // report — and `shipped_services_lint_clean` already refuses to let
            // one reach a release. The log line matters for an operator pointing
            // `services_dir` at templates of their own, which never passed our
            // CI. See D67.
            for w in crate::openapi::lint_extensions(&doc) {
                tracing::warn!(
                    file = %path.display(),
                    code = %w.code,
                    path = %w.path,
                    message = %w.message,
                    "shipped service template declares something nothing reads"
                );
            }

            // Expand `${VAR}` before compile, so `servers[].url` is already the
            // host this deployment actually talks to by the time `hosts` is
            // derived from it — the platform-credential check compares against
            // `hosts[0]`, so expanding any later would reintroduce the drift
            // this mechanism exists to remove.
            if let Err(issues) = template_vars::expand(&mut doc, &vars) {
                tracing::error!(
                    file = %path.display(),
                    issues = ?issues,
                    "template variable expansion failed; skipping"
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

        // Inject the synthetic `http` pseudo-service so Mode A's resolution
        // path can flow through the same Service+HTTP-verb code as real
        // services. Only injected if no shipped YAML claimed the key.
        services
            .entry(HTTP_PSEUDO_SERVICE.to_string())
            .or_insert_with(http_pseudo_service);

        Ok(Self { services, vars })
    }

    /// Build a registry that contains only the synthetic `http` pseudo-service.
    /// Used by tests / contexts that don't load shipped templates from disk.
    pub fn with_builtins() -> Self {
        let mut services = HashMap::new();
        let def = http_pseudo_service();
        services.insert(def.key.clone(), def);
        Self {
            services,
            vars: Vars::empty(),
        }
    }

    /// The deployment's template variables, for the paths that expand
    /// org/user-authored templates at resolve time.
    pub fn vars(&self) -> &Vars {
        &self.vars
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
mod tests;
