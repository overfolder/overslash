//! Service/instance lookup and HTTP-verb host/path resolution.

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{AppState, error::AppError, extractors::AuthContext, services::group_ceiling};

use super::errors::*;

/// Rebind the caller's identity to the service instance owner when an org
/// admin is invoking another user's service **via the explicit `service_id`
/// path**. Returns the (possibly swapped) `(identity, identity_id,
/// ceiling_user_id, scope)` tuple — the rest of the handler can keep
/// operating on these without an explicit `if admin { ... }` at every gate.
///
/// Why gated on `explicit_via_uuid`: when the caller reached the instance
/// through the name resolver, success already proves visibility — they
/// either own it, share a ceiling user with it, or have a group grant. A
/// non-admin agent invoking a group-granted, cross-user service is the
/// intended cross-user flow and must keep working (see
/// `tests/cross_user_group_reauth.rs`). The admin-as-owner rebind only
/// kicks in for the new UUID branch, which deliberately skips visibility
/// checks so the dashboard's "Show all users' services" view can drive
/// invocations — that path is the one that needs the admin gate.
pub(super) async fn apply_owner_impersonation(
    scope: &OrgScope,
    identity: overslash_db::repos::identity::IdentityRow,
    identity_id: Uuid,
    ceiling_user_id: Uuid,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    explicit_via_uuid: bool,
) -> Result<
    (
        overslash_db::repos::identity::IdentityRow,
        Uuid,
        Uuid,
        OrgScope,
    ),
    AppError,
> {
    if !explicit_via_uuid {
        return Ok((identity, identity_id, ceiling_user_id, scope.clone()));
    }
    let Some(owner) = instance.and_then(|i| i.owner_identity_id) else {
        return Ok((identity, identity_id, ceiling_user_id, scope.clone()));
    };
    if owner == ceiling_user_id {
        return Ok((identity, identity_id, ceiling_user_id, scope.clone()));
    }
    if !identity.is_org_admin {
        return Err(AppError::Forbidden(
            "service is owned by another user; only org admins can invoke it".into(),
        ));
    }
    let owner_identity = scope
        .get_identity(owner)
        .await?
        .ok_or_else(|| AppError::NotFound("service owner identity not found".into()))?;
    let owner_ceiling = group_ceiling::ceiling_user_id_from_identity(&owner_identity)?;
    Ok((
        owner_identity,
        owner,
        owner_ceiling,
        scope.with_impersonator(identity_id),
    ))
}

/// Look up a service instance for an action call.
///
/// When `service_id` is set, do an **org-scoped UUID lookup** — the only path
/// that lets an org admin reach an instance owned by another user. Without
/// `service_id`, fall back to the caller-scoped name resolver, which honors
/// the user-shadows-org semantics every other call site has always used.
pub(super) async fn resolve_instance_for_call(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Uuid,
    service_id: Option<Uuid>,
    service_key: &str,
) -> Result<Option<overslash_db::repos::service_instance::ServiceInstanceRow>, AppError> {
    if let Some(id) = service_id {
        return Ok(scope.get_service_instance(id).await?);
    }
    Ok(scope
        .resolve_service_instance_by_name(identity_id, Some(ceiling_user_id), service_key)
        .await?)
}

/// Look up the service template + instance for a Service + HTTP verb call.
/// Mirrors the (service, action) arm's resolution, minus the action lookup.
pub(super) async fn resolve_service_for_verb_shape(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    scope: &OrgScope,
    ceiling_user_id: Uuid,
    service_id: Option<Uuid>,
    service_key: &str,
) -> Result<
    (
        Option<overslash_db::repos::service_instance::ServiceInstanceRow>,
        overslash_core::types::ServiceDefinition,
    ),
    AppError,
> {
    let instance = resolve_instance_for_call(
        scope,
        auth.identity_id,
        ceiling_user_id,
        service_id,
        service_key,
    )
    .await?;

    let svc = if let Some(ref inst) = instance {
        crate::routes::templates::resolve_template_definition(
            state,
            ext,
            auth.org_id,
            auth.identity_id,
            &inst.template_key,
        )
        .await?
    } else {
        let from_template = crate::routes::templates::resolve_template_definition(
            state,
            ext,
            auth.org_id,
            auth.identity_id,
            service_key,
        )
        .await
        .ok();
        match from_template.or_else(|| state.registry.get(service_key).cloned()) {
            Some(s) => s,
            None => {
                let available =
                    caller_visible_instance_names(scope, auth.identity_id, Some(ceiling_user_id))
                        .await?;
                return Err(unknown_service_error(service_key, available));
            }
        }
    };
    Ok((instance, svc))
}

/// Resolve the path + outgoing URL for a Service + HTTP verb call.
///
/// Two input shapes:
/// - `path: "/x"` → prefixes the org layer's `instance_defaults.url` if it has
///   one, else the first of `svc.hosts`.
/// - `url: "https://h/x"` → host must match any of `svc.hosts` (the fold unions
///   a layer's default endpoint into `hosts`, so an org gateway is nameable
///   here too).
///
/// Returns `(path, url)`. `path` is what permission keys derive from
/// (`{service}:{METHOD}:{path}`); `url` is what the executor sends.
///
/// The synthetic `http` pseudo-service ships with `hosts: []` — the caller
/// supplies the full URL on every call, no host binding. In that case the
/// returned `path` is `host[:port]/path?query` (no leading `/`) so the
/// derived permission key matches the legacy `http:{METHOD}:{host}{path}`
/// shape from before the Mode-A collapse.
pub(super) fn resolve_verb_host_and_path(
    svc: &overslash_core::types::ServiceDefinition,
    service_key: &str,
    url: &Option<String>,
    path: &Option<String>,
) -> Result<(String, String), AppError> {
    if svc.hosts.is_empty() {
        // `http` pseudo-service: no host binding. Caller MUST supply `url`;
        // a path-only request has no base to prefix.
        let u = match (url, path) {
            (Some(u), None) => u,
            (None, Some(_)) => {
                return Err(AppError::BadRequest(format!(
                    "service '{service_key}' has no hosts; supply a full 'url' instead of 'path'"
                )));
            }
            (Some(_), Some(_)) => {
                return Err(AppError::BadRequest(
                    "'url' and 'path' are mutually exclusive — pick one".into(),
                ));
            }
            (None, None) => {
                return Err(AppError::BadRequest(format!(
                    "service '{service_key}' requires 'url' (raw HTTP)"
                )));
            }
        };
        let parsed =
            url::Url::parse(u).map_err(|e| AppError::BadRequest(format!("invalid 'url': {e}")))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(AppError::BadRequest(format!(
                "'url' scheme must be http or https (got '{}')",
                parsed.scheme()
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| AppError::BadRequest("'url' has no host".into()))?;
        // Build `host[:port]/path?query` — the `path` segment that feeds
        // the derived permission key (`{service}:{METHOD}:{path}`).
        let mut perm_path = match parsed.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        perm_path.push_str(parsed.path());
        if let Some(q) = parsed.query() {
            perm_path.push('?');
            perm_path.push_str(q);
        }
        return Ok((perm_path, u.clone()));
    }
    match (url, path) {
        (Some(_), Some(_)) => Err(AppError::BadRequest(
            "'url' and 'path' are mutually exclusive — pick one".into(),
        )),
        (None, None) => Err(AppError::BadRequest(
            "service + HTTP verb requires either 'path' or 'url'".into(),
        )),
        (None, Some(p)) => {
            if !p.starts_with('/') {
                return Err(AppError::BadRequest(format!(
                    "'path' must start with '/' (got '{p}')"
                )));
            }
            // An org layer's default endpoint wins over the template's first
            // host, so a verb-shape call lands on the same deployment an
            // action-shape call would. (The instance is not consulted here —
            // the verb shape resolves against the template, not an instance.)
            let url = match svc
                .instance_defaults
                .as_ref()
                .and_then(|d| d.url.as_deref())
            {
                Some(base) => format!("{}{p}", base.trim_end_matches('/')),
                None => {
                    let host = &svc.hosts[0];
                    if host.contains("://") {
                        format!("{host}{p}")
                    } else {
                        format!("https://{host}{p}")
                    }
                }
            };
            Ok((p.clone(), url))
        }
        (Some(u), None) => {
            let parsed = url::Url::parse(u)
                .map_err(|e| AppError::BadRequest(format!("invalid 'url': {e}")))?;
            let req_host = parsed
                .host_str()
                .ok_or_else(|| AppError::BadRequest("'url' has no host".into()))?;
            // Match host AND port: a `svc.hosts` entry of `api.example.com`
            // implies the scheme's default port (443/https, 80/http); an
            // entry of `host:port` requires that exact port. Without this,
            // a caller could redirect the bearer to an arbitrary port on
            // an allowed host (e.g. an internal admin service).
            let req_port = parsed.port_or_known_default();
            let host_matches = svc.hosts.iter().any(|h| {
                let with_scheme = if h.contains("://") {
                    h.to_string()
                } else {
                    format!("https://{h}")
                };
                let Ok(allowed) = url::Url::parse(&with_scheme) else {
                    return false;
                };
                allowed.host_str() == Some(req_host) && allowed.port_or_known_default() == req_port
            });
            if !host_matches {
                let req_authority = match parsed.port() {
                    Some(p) => format!("{req_host}:{p}"),
                    None => req_host.to_string(),
                };
                return Err(AppError::BadRequest(format!(
                    "host '{req_authority}' is not in service '{service_key}' hosts (allowed: {})",
                    svc.hosts.join(", ")
                )));
            }
            let mut path = parsed.path().to_string();
            if let Some(q) = parsed.query() {
                path.push('?');
                path.push_str(q);
            }
            Ok((path, u.clone()))
        }
    }
}

#[cfg(test)]
mod verb_host_path_tests {
    use super::*;
    use overslash_core::types::ServiceDefinition;

    fn svc_with_hosts(hosts: Vec<&str>) -> ServiceDefinition {
        ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "github".into(),
            display_name: "GitHub".into(),
            description: None,
            hosts: hosts.into_iter().map(String::from).collect(),
            category: None,
            hidden: false,
            auth: vec![],
            actions: std::collections::HashMap::new(),
            runtime: overslash_core::types::Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    #[test]
    fn path_form_prefixes_first_host() {
        let svc = svc_with_hosts(vec!["api.github.com"]);
        let (path, url) =
            resolve_verb_host_and_path(&svc, "github", &None, &Some("/repos/x/pulls".into()))
                .unwrap();
        assert_eq!(path, "/repos/x/pulls");
        assert_eq!(url, "https://api.github.com/repos/x/pulls");
    }

    #[test]
    fn url_form_accepts_matching_host() {
        let svc = svc_with_hosts(vec!["api.github.com"]);
        let (path, url) = resolve_verb_host_and_path(
            &svc,
            "github",
            &Some("https://api.github.com/repos/x/pulls".into()),
            &None,
        )
        .unwrap();
        assert_eq!(path, "/repos/x/pulls");
        assert_eq!(url, "https://api.github.com/repos/x/pulls");
    }

    #[test]
    fn url_form_rejects_unallowed_host() {
        let svc = svc_with_hosts(vec!["api.github.com"]);
        let err = resolve_verb_host_and_path(
            &svc,
            "github",
            &Some("https://attacker.example.com/exfil".into()),
            &None,
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    /// Port-bypass closure: a `svc.hosts` entry without a port implies the
    /// scheme's default; a caller cannot redirect the bearer to an
    /// arbitrary port on an allowed host.
    #[test]
    fn url_form_rejects_arbitrary_port_on_allowed_host() {
        let svc = svc_with_hosts(vec!["api.github.com"]);
        let err = resolve_verb_host_and_path(
            &svc,
            "github",
            &Some("https://api.github.com:8443/repos/x/pulls".into()),
            &None,
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn url_form_accepts_explicit_port_when_template_specifies_it() {
        let svc = svc_with_hosts(vec!["http://localhost:1234"]);
        let (_, url) = resolve_verb_host_and_path(
            &svc,
            "local",
            &Some("http://localhost:1234/api".into()),
            &None,
        )
        .unwrap();
        assert_eq!(url, "http://localhost:1234/api");
    }

    #[test]
    fn url_form_rejects_port_mismatch_when_template_specifies_port() {
        let svc = svc_with_hosts(vec!["http://localhost:1234"]);
        let err = resolve_verb_host_and_path(
            &svc,
            "local",
            &Some("http://localhost:9999/api".into()),
            &None,
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn url_and_path_together_rejected() {
        let svc = svc_with_hosts(vec!["api.github.com"]);
        let err = resolve_verb_host_and_path(
            &svc,
            "github",
            &Some("https://api.github.com/x".into()),
            &Some("/x".into()),
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn path_must_start_with_slash() {
        let svc = svc_with_hosts(vec!["api.github.com"]);
        let err =
            resolve_verb_host_and_path(&svc, "github", &None, &Some("repos".into())).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }
}
