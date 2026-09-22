//! Tests for [`super::ServiceRegistry`], including the corpus gates that run
//! over the shipped `services/` tree.
//!
//! Split out of `mod.rs` to keep both halves navigable — the file is
//! overwhelmingly tests, and the gate that caps a source file at a thousand
//! lines does not distinguish.

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

    let reg = ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
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
    let reg = ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
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

    let reg = ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
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

    let reg = ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
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

    let reg = ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
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

    let reg = ServiceRegistry::load_from_dir(dir.path(), crate::template_vars::Vars::for_tests())
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
fn every_shipped_template_resolves_to_a_shipped_icon() {
    // Catches the two ways this silently degrades: a renamed asset (the
    // implicit `builtin:<key>` rule stops matching and the service drops to
    // a letter tile), and an `icon:` naming an asset nobody shipped.
    //
    // Templates listed as `pending` in assets/service-icons/manifest.json
    // legitimately have no mark yet and are expected to be iconless.
    const EXPECTED_WITHOUT_ICON: &[&str] = &["eventbrite", "linkedin", "outlook", "slack"];

    let reg = ServiceRegistry::load_from_dir(&shipped_services_dir(), Vars::for_tests()).unwrap();

    for def in reg.all() {
        let key = def.key.as_str();
        match &def.icon {
            None => assert!(
                EXPECTED_WITHOUT_ICON.contains(&key),
                "template '{key}' has no icon; add one to \
                     assets/service-icons/manifest.json or list it as pending"
            ),
            Some(icon) => assert!(
                icon.is_known_builtin()
                    || matches!(icon, crate::service_icon::ServiceIcon::Remote { .. }),
                "template '{key}' points at '{icon}', which is not a shipped asset"
            ),
        }
    }
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
        &crate::permissions::ScopeValues::resolved(&crate::types::ScopeParams::default(), &params),
    );
    assert_eq!(keys.len(), 1, "no scope_param passed → single wildcard key");
    let keys = crate::permissions::PermissionKey::from_service_action(
        "email",
        "send",
        &crate::permissions::ScopeValues::resolved(&send.scope_param, &params),
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
    //
    // Its one-level-down analogue is `shipped_services_lint_clean` (in
    // `template_validation::yaml`), for the template that loads fine and
    // quietly does less than it says — this test catches a template that
    // vanishes, that one catches a key nothing reads.
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
