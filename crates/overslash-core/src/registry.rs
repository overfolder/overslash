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
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_yaml(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn shipped_services_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services")
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
      x-overslash-template:
        lang: jq
        expr: '"Bearer " + .token'
      default_secret_name: github_token
paths:
  /user/repos:
    get:
      operationId: list_repos
      summary: List repositories
      risk: read
"#,
        );

        let reg =
            ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
                .unwrap();
        // 1 from YAML + 1 synthetic `http` pseudo-service.
        assert_eq!(reg.len(), 2);
        let gh = reg.get("github").unwrap();
        assert_eq!(gh.display_name, "GitHub");
        assert_eq!(gh.hosts, vec!["api.github.com"]);
        assert!(gh.actions.contains_key("list_repos"));
    }

    #[test]
    fn synthetic_http_pseudo_service_is_registered() {
        // `load_from_dir` always injects `http` when no shipped YAML claims
        // the key, so the actions handler can resolve `service: "http"`
        // through the standard registry path.
        let dir = TempDir::new().unwrap();
        let reg =
            ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
                .unwrap();
        let http = reg
            .get("http")
            .expect("synthetic `http` pseudo-service missing");
        assert_eq!(http.display_name, "Raw HTTP");
        assert!(http.hosts.is_empty());
        assert!(http.auth.is_empty());
        assert!(http.actions.is_empty());
    }

    #[test]
    fn with_builtins_contains_only_http() {
        let reg = ServiceRegistry::with_builtins();
        assert_eq!(reg.len(), 1);
        assert!(reg.get("http").is_some());
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

        let reg =
            ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
                .unwrap();
        // The synthetic `http` pseudo-service has no hosts so it never
        // matches `find_by_host` — counts stay focused on real services.
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

        let reg =
            ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
                .unwrap();
        let gh = reg.get("github").unwrap();
        let create_pr = gh.actions.get("create_pull_request").unwrap();
        assert_eq!(create_pr.scope_param, "repo".into());
        let list_repos = gh.actions.get("list_repos").unwrap();
        assert!(list_repos.scope_param.is_empty());
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

        let reg =
            ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
                .unwrap();
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

        let reg =
            ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
                .unwrap();
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
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();
        assert!(!reg.is_empty(), "no shipped templates loaded");
    }

    #[test]
    fn shipped_email_host_comes_from_the_deployment_variable() {
        // The whole point of D44: `hosts[0]` — which is what
        // `Config::platform_credential_for` compares the outgoing URL against
        // — must be the host THIS deployment configured, not a literal baked
        // into the YAML. Before this, dev shipped `mailbox.overslash.com`
        // while deploying `mailbox.dev.overslash.com`, so dev instances both
        // hit the wrong gateway and were denied the platform key.
        let reg = ServiceRegistry::load_from_dir(
            &shipped_services_dir(),
            Vars::from_pairs([("MAILBOX_HOST", "mailbox.dev.overslash.com")]),
        )
        .unwrap();
        let email = reg.get("email").expect("email template registered");
        assert_eq!(email.hosts, vec!["mailbox.dev.overslash.com".to_string()]);
    }

    #[test]
    fn shipped_email_is_skipped_when_its_host_variable_is_unset() {
        // Deliberately not a fallback to the prod host: a deployment that
        // hasn't configured a gateway has no `email` service, rather than one
        // silently pointed at somebody else's mailbox gateway.
        let reg = ServiceRegistry::load_from_dir(&shipped_services_dir(), Vars::empty()).unwrap();
        assert!(reg.get("email").is_none(), "email loaded without a host");
        // Only `email` is affected — templates with literal hosts still load,
        // so one unset variable can't empty the catalog.
        assert!(reg.get("github").is_some());
    }

    #[test]
    fn shipped_metabase_loads_host_less_when_its_url_variable_is_unset() {
        // The `${VAR?}` half of D44, and the reason metabase does NOT use the
        // no-fallback form email does: Metabase is self-hosted, so a deployment
        // that sets nothing should still be able to OFFER the template and ask
        // for the endpoint at instantiation — not lose it entirely.
        let reg = ServiceRegistry::load_from_dir(&shipped_services_dir(), Vars::empty()).unwrap();
        let metabase = reg.get("metabase").expect("metabase still registered");
        assert!(
            metabase.hosts.is_empty(),
            "unset ${{METABASE_URL?}} should leave no host, got {:?}",
            metabase.hosts
        );
        // Host-less but otherwise whole — the actions are still there to bind
        // once an instance supplies a `url`.
        assert!(!metabase.actions.is_empty());
    }

    #[test]
    fn shipped_metabase_takes_its_host_from_the_deployment_variable() {
        let reg = ServiceRegistry::load_from_dir(
            &shipped_services_dir(),
            Vars::from_pairs([
                ("MAILBOX_HOST", "mailbox.overslash.com"),
                ("METABASE_URL", "https://mb.example.com"),
            ]),
        )
        .unwrap();
        assert_eq!(
            reg.get("metabase").map(|m| m.hosts.clone()),
            Some(vec!["mb.example.com".to_string()])
        );
    }

    #[test]
    fn shipped_email_declares_instance_pinnable_mailbox_endpoint() {
        // The email template reaches overfwd, which resolves the IMAP/SMTP
        // endpoint by autoconfig unless the request carries `X-Mailbox-Imap` /
        // `X-Mailbox-Smtp`. Autoconfig cannot resolve a self-hosted mailbox, so
        // without these params the template can only ever reach public
        // providers. They must stay header-located (a body param would be sent
        // as JSON and silently ignored by the gateway) and instance-pinnable
        // (an agent has no way to know its org's mail host).
        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();
        let email = reg.get("email").expect("email template registered");

        // All three operations carry them — a pin that only reached `search`
        // would leave `send` silently autoconfiguring against a host the org
        // never chose.
        for action_key in ["search", "get", "send"] {
            let action = &email.actions[action_key];
            for param_name in ["X-Mailbox-Imap", "X-Mailbox-Smtp"] {
                let p = action
                    .params
                    .get(param_name)
                    .unwrap_or_else(|| panic!("email.{action_key} must declare {param_name}"));
                assert_eq!(
                    p.location,
                    crate::types::ParamLocation::Header,
                    "email.{action_key}.{param_name} must be header-located"
                );
                assert!(
                    p.instance_config,
                    "email.{action_key}.{param_name} must be instance-pinnable"
                );
                assert!(
                    !p.required,
                    "email.{action_key}.{param_name} must stay optional — \
                     autoconfig is the default path for public providers"
                );
            }
        }
    }

    /// The search parameter is named for what it is. `query` implied a
    /// free-text box, so an agent searched for a sender by name, got `200 []`,
    /// and concluded the mailbox was empty. The old name stays accepted so no
    /// caller breaks, and the explanation lives on `description` because that
    /// is the only string about an action the model ever sees.
    #[test]
    fn shipped_email_search_names_its_imap_criteria_and_keeps_query_accepted() {
        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();
        let search = &reg.get("email").expect("email template").actions["search"];

        let criteria = search
            .params
            .get("criteria")
            .expect("email.search must declare `criteria`");
        assert!(
            !search.params.contains_key("query"),
            "`query` must be an alias, not a second declared param"
        );
        assert!(
            criteria.aliases.contains(&"query".to_string()),
            "the old name must stay accepted, got {:?}",
            criteria.aliases
        );
        assert_eq!(criteria.default, Some(serde_json::json!("ALL")));

        // The agent-facing text must say the thing that would have prevented
        // the burned calls, and must not be the terse label.
        assert!(
            search.description.contains("IMAP SEARCH"),
            "description must name the syntax: {:?}",
            search.description
        );
        assert_ne!(
            Some(search.description.as_str()),
            search.summary.as_deref(),
            "the approval label must stay short and separate from the explainer"
        );
    }

    /// Every instance of this template renders the same display name, because
    /// the name belongs to the template. Marking the mailbox address as the
    /// identity config var is what lets discovery tell three mailboxes apart.
    #[test]
    fn shipped_email_marks_the_mailbox_address_as_its_account_identity() {
        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();
        let email = reg.get("email").expect("email template");
        assert_eq!(email.identity_config_key(), Some("mailbox_user"));
    }

    /// Permission keys for a send are derived per recipient, so a grant can be
    /// scoped to one correspondent or one domain.
    #[test]
    fn shipped_email_send_scopes_permissions_by_recipient() {
        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();
        let send = &reg.get("email").expect("email template").actions["send"];

        assert_eq!(
            send.scope_param
                .refs()
                .iter()
                .map(|r| (r.param.as_str(), r.label.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("to", "recipient"),
                ("cc", "recipient"),
                ("bcc", "recipient")
            ],
            "every header is scoped, and all three share one namespace"
        );
        for header in ["to", "cc", "bcc"] {
            assert_eq!(
                send.params[header].param_type, "array",
                "the recipient fan-out relies on `{header}` lowering as an array"
            );
        }

        let mut params = std::collections::HashMap::new();
        params.insert(
            "to".to_string(),
            serde_json::json!(["a@example.com", "b@example.org"]),
        );
        params.insert("cc".to_string(), serde_json::json!(["a@example.com"]));
        params.insert("bcc".to_string(), serde_json::json!(["c@example.net"]));
        let keys = crate::permissions::PermissionKey::from_service_action(
            "email",
            "send",
            &crate::types::ScopeParams::default(),
            &params,
        );
        assert_eq!(keys.len(), 1, "no scope_param passed → single wildcard key");
        let keys = crate::permissions::PermissionKey::from_service_action(
            "email",
            "send",
            &send.scope_param,
            &params,
        );
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "email:send:recipient=a@example.com",
                "email:send:recipient=b@example.org",
                "email:send:recipient=c@example.net"
            ],
            "cc/bcc mint keys too, and the address on both `to` and `cc` collapses to one"
        );
    }

    #[test]
    fn shipped_telegram_send_message_declares_param_aliases() {
        // Pin the ergonomics fix from the burned-approval traces: the Telegram
        // `send_message` tool must accept `text`/`body` as aliases for its
        // canonical `message` param (agents reach for Telegram's Bot-API field
        // name `text`) and `to`/`chat` for `chat_id`. If a resync or edit drops
        // these, this fails loudly instead of at call time.
        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();
        let tg = reg.get("telegram").expect("telegram template registered");
        let send = &tg.actions["send_message"];
        assert!(
            send.params["message"].aliases.contains(&"text".to_string()),
            "send_message.message must alias `text`, got {:?}",
            send.params["message"].aliases
        );
        assert!(
            send.params["chat_id"].aliases.contains(&"to".to_string()),
            "send_message.chat_id must alias `to`, got {:?}",
            send.params["chat_id"].aliases
        );
    }

    #[test]
    fn shipped_services_have_no_silent_skips() {
        // `load_from_dir` logs-and-skips any file that fails to
        // parse/compile/validate, so a broken template silently disappears from
        // the registry (and `shipped_services_load_clean` still passes because
        // it only checks non-emptiness). Assert every shipped `*.yaml` both
        // validates AND lands in the registry under its declared key, so a
        // validation regression fails loudly here instead of at call time.
        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();

        for entry in std::fs::read_dir(&services_dir).unwrap() {
            let path = entry.unwrap().path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml" || e == "yml");
            if !is_yaml {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let report = crate::template_validation::validate_template_yaml(
                &source,
                &crate::template_vars::Vars::for_tests(),
            );
            assert!(
                report.valid,
                "{} failed validation (would be silently skipped): {:#?}",
                path.display(),
                report.errors
            );
            // The compiled key must be registered — proves the file wasn't dropped.
            let key = crate::openapi::parse_yaml(&source)
                .ok()
                .and_then(|mut doc| {
                    crate::openapi::normalize_aliases(&mut doc);
                    doc.get("info")
                        .and_then(|i| i.get("x-overslash-key"))
                        .and_then(|k| k.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| panic!("{}: missing info.key", path.display()));
            assert!(
                reg.get(&key).is_some(),
                "{} declares key '{key}' but it is not in the registry",
                path.display()
            );
        }
    }

    #[test]
    fn shipped_mutating_actions_declare_disclose() {
        // Escape hatch for actions where disclosure is intentionally
        // omitted. Format: "service_key:action_key". Keep empty; add
        // entries only with a comment explaining why review disclosure
        // is impossible for that action.
        const ALLOW_MISSING: &[&str] = &[];

        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();

        let mut missing: Vec<String> = Vec::new();
        for def in reg.all() {
            // Platform-runtime actions cannot carry disclose blocks:
            // extract_platform_action drops them at parse time and
            // compute_approval_detail never runs disclose filters for the
            // platform projection ({runtime, action, params, service}
            // already is the full reviewable payload).
            if matches!(def.runtime, Runtime::Platform) {
                continue;
            }
            for (key, action) in &def.actions {
                let id = format!("{}:{}", def.key, key);
                // `dynamic` counts as mutating here: a per-call-classified
                // action can write, so its approvals need disclose too.
                if action.risk.display_risk().is_mutating()
                    && action.disclose.is_empty()
                    && !ALLOW_MISSING.contains(&id.as_str())
                {
                    missing.push(id);
                }
            }
        }
        missing.sort();
        assert!(
            missing.is_empty(),
            "every shipped write/delete action must declare `disclose:` so \
             approval reviewers see what the action will do; missing: {missing:#?}"
        );
    }

    #[test]
    fn shipped_github_templates_auth() {
        use crate::types::ServiceAuth;

        let services_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let reg =
            ServiceRegistry::load_from_dir(&services_dir, crate::template_vars::Vars::for_tests())
                .unwrap();

        // `github` targets GitHub App user-to-server tokens: no OAuth scopes
        // (the app's permissions + installations govern access) plus an
        // installation diagnostic action.
        let gh = reg.get("github").expect("github template missing");
        match gh
            .auth
            .iter()
            .find(|a| matches!(a, ServiceAuth::OAuth { .. }))
        {
            Some(ServiceAuth::OAuth {
                provider, scopes, ..
            }) => {
                assert_eq!(provider, "github");
                assert!(
                    scopes.is_empty(),
                    "GitHub App template must not declare OAuth scopes, got {scopes:?}"
                );
            }
            _ => panic!("github template must declare OAuth auth"),
        }
        assert!(gh.actions.contains_key("list_installations"));
        assert!(!gh.hidden, "github template must not be hidden");

        // `github_legacy_oauth` keeps the classic OAuth App scopes and is
        // marked `x-overslash-hidden: true` so it stays out of agent-facing
        // catalogs while remaining reachable by key.
        let legacy = reg
            .get("github_legacy_oauth")
            .expect("github_legacy_oauth template missing");
        assert!(legacy.hidden, "github_legacy_oauth must compile as hidden");
        match legacy
            .auth
            .iter()
            .find(|a| matches!(a, ServiceAuth::OAuth { .. }))
        {
            Some(ServiceAuth::OAuth {
                provider, scopes, ..
            }) => {
                assert_eq!(provider, "github");
                for s in ["repo", "read:user", "user:email"] {
                    assert!(
                        scopes.iter().any(|x| x == s),
                        "legacy template missing scope {s}"
                    );
                }
            }
            _ => panic!("github_legacy_oauth template must declare OAuth auth"),
        }
    }
}
