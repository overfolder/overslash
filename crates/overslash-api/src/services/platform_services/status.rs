//! Credential-health classification: effective-scope resolution, per-action
//! scope coverage, and the pure `CredentialsStatus` classifier.

use super::templates::*;
use super::*;

/// Compute credential-health for a service instance against its template.
///
/// Loads the connection (if any) and template, then defers to
/// [`derive_credentials_status`] for the pure classification logic.
pub async fn compute_credentials_status(
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    scope: &OrgScope,
    row: &ServiceInstanceRow,
    template_owner: Option<Uuid>,
) -> Option<CredentialsStatus> {
    let template =
        resolve_template_definition(db, registry, row.org_id, template_owner, &row.template_key)
            .await
            .ok()?;
    let conn_scopes = resolve_effective_scopes(db, scope, &template, row).await;
    let scopes = match &conn_scopes {
        None => ScopeKnowledge::NoConnection,
        Some(opt) => scope_knowledge(opt.as_deref()),
    };
    derive_credentials_status(
        &template,
        scopes,
        &row.credentials,
        row.secret_name.as_deref(),
    )
}

/// Granted scopes of the connection the *execution* path would actually use.
///
/// Mirrors `resolve_service_auth` / `check_required_scopes` at call time: an
/// explicit `connection_id` binding wins (resolved org-scoped, so agent-owned
/// connections still classify — see PR #321); otherwise an OAuth template
/// auto-resolves the *owner identity's* connection for its provider. Without
/// this, an instance that was never explicitly bound but works via provider
/// auto-resolve (e.g. a `google_calendar` instance with `connection_id = NULL`
/// when the owner has a Google connection) was misreported as needing setup —
/// both on the dashboard badge and on the agent-facing `service_status`.
/// Returns `None` when no connection backs the instance, `Some(None)` when one
/// does but its scopes are unknown, and `Some(Some(scopes))` for a known set.
pub(crate) async fn resolve_effective_scopes(
    db: &sqlx::PgPool,
    scope: &OrgScope,
    template: &ServiceDefinition,
    row: &ServiceInstanceRow,
) -> Option<Option<Vec<String>>> {
    if let Some(conn_id) = row.connection_id {
        return scope
            .get_connection(conn_id)
            .await
            .ok()
            .flatten()
            .map(|c| c.scopes);
    }
    // Opted out of the default-connection fallback: execution resolves no
    // connection, so the classifier reports NoConnection (mirrors
    // `resolve_instance_auth`). Without this the badge would read "ok" while
    // calls 401.
    if !row.use_default_connection {
        return None;
    }
    let provider = template_oauth_provider(template)?;
    let owner = row.owner_identity_id?;
    UserScope::new(row.org_id, owner, db.clone())
        .find_my_connection_by_provider(provider)
        .await
        .ok()
        .flatten()
        .map(|c| c.scopes)
}

/// What is known about a connection's granted scopes when classifying a
/// service instance's credential health. Distinguishes "no connection at all"
/// from "a connection exists but its granted scopes are unknown" (an imported
/// token vaulted without declaring scopes) — the latter gets the benefit of the
/// doubt, mirroring the call-time scope-gate.
#[derive(Debug, Clone, Copy)]
pub enum ScopeKnowledge<'a> {
    /// No connection is bound and none auto-resolves.
    NoConnection,
    /// A connection exists but its granted scopes weren't recorded.
    Unknown,
    /// The known granted scope set (possibly empty).
    Known(&'a [String]),
}

/// Per-action scope coverage, surfaced at discovery time so an agent can see
/// an action is uncovered *before* calling it (instead of after a raw upstream
/// 403). Mirrors the call-time gate in `routes/actions/auth.rs`.
#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ScopeCoverage {
    /// Every required scope is granted (or the action declares none).
    Covered,
    /// At least one required scope is missing — calling it will 403.
    NeedsReconnect,
    /// A connection exists but its granted scopes weren't recorded — same
    /// benefit-of-the-doubt the call-time gate gives, surfaced honestly.
    Unknown,
}

/// Coverage of a single action's `required_scopes` against the connection's
/// scope knowledge, plus the missing-scope delta (empty unless
/// [`ScopeCoverage::NeedsReconnect`]). Shared by [`derive_credentials_status`]
/// and the discovery endpoints (`search`, `list_service_actions`) so the
/// classification stays identical at discovery time and call time.
pub fn action_scope_coverage(
    action: &ServiceAction,
    scopes: ScopeKnowledge<'_>,
) -> (ScopeCoverage, Vec<String>) {
    if action.required_scopes.is_empty() {
        return (ScopeCoverage::Covered, Vec::new());
    }
    let granted = match scopes {
        ScopeKnowledge::Known(list) => list,
        // No bound connection, or one whose scopes weren't recorded: we can't
        // prove a gap, so don't cry wolf — report Unknown.
        ScopeKnowledge::NoConnection | ScopeKnowledge::Unknown => {
            return (ScopeCoverage::Unknown, Vec::new());
        }
    };
    let granted_set: HashSet<&str> = granted.iter().map(String::as_str).collect();
    let missing: Vec<String> = action
        .required_scopes
        .iter()
        .filter(|s| !granted_set.contains(s.as_str()))
        .cloned()
        .collect();
    if missing.is_empty() {
        (ScopeCoverage::Covered, Vec::new())
    } else {
        (ScopeCoverage::NeedsReconnect, missing)
    }
}

/// Pure classifier: takes a template + scope knowledge + the instance's
/// credential bindings and returns a [`CredentialsStatus`] or `None` when the
/// template has no auth scheme to evaluate.
pub fn derive_credentials_status(
    template: &ServiceDefinition,
    scopes: ScopeKnowledge<'_>,
    credentials: &CredentialsMap,
    secret_name: Option<&str>,
) -> Option<CredentialsStatus> {
    // An OAuth MCP server (mcp.auth kind: oauth) needs the same connection
    // dance as an HTTP OAuth template, so fold it into `has_oauth`.
    let mcp_oauth = matches!(
        template.mcp.as_ref().map(|m| &m.auth),
        Some(McpAuth::OAuth { .. })
    );
    let has_oauth = mcp_oauth
        || template
            .auth
            .iter()
            .any(|a| matches!(a, ServiceAuth::OAuth { .. }));
    let has_secret = template
        .auth
        .iter()
        .any(|a| matches!(a, ServiceAuth::Secret { .. }));
    // A required credential slot is unbound when the execution-time resolution
    // chain (`credentials[slot]` → legacy `secret_name` for instance-source
    // → fixed `default_secret_name` for org-source) yields no name. Mirrors
    // `resolve_instance_auth`; whether the named secret actually exists in
    // the vault is a send-time concern a pure classifier can't check. In
    // particular a template whose slots are all org-source needs no instance
    // binding at all — it must NOT report NeedsAuthentication just because the
    // instance's scalar `secret_name` is empty.
    //
    // Per *slot*, not per scheme: a header joined from a username and a
    // password is only bound once both halves are.
    // Counted over ALL instance-source slots, including the unkeyed one a
    // programmatically-built template carries — the scalar alias stood for
    // that credential too, so excluding it would report every such instance
    // unbound.
    let single_instance_slot = template
        .all_slots()
        .iter()
        .filter(|s| s.source == SecretSource::Instance)
        .count()
        <= 1;
    let secret_unbound = template.all_slots().into_iter().any(|slot| {
        !slot.optional
            && credentials.get(&slot.key).is_none_or(|n| n.is_empty())
            && match slot.source {
                // The scalar alias only ever stood for a single credential, so
                // it cannot vouch for one half of a composed one.
                SecretSource::Instance => {
                    !single_instance_slot || secret_name.is_none() || secret_name == Some("")
                }
                SecretSource::Org => slot.default_secret_name.is_empty(),
            }
    });
    let mcp_bearer = matches!(
        template.mcp.as_ref().map(|m| &m.auth),
        Some(McpAuth::Bearer { .. })
    );
    let no_secret = secret_name.is_none() || secret_name == Some("");

    let granted_list = match scopes {
        // No connection bound and no inline secret: a freshly-instantiated
        // service for an auth-bearing template needs the OAuth dance / secret to
        // be provided. Surface that explicitly so the agent doesn't guess.
        ScopeKnowledge::NoConnection => {
            if has_oauth {
                return Some(CredentialsStatus::NeedsAuthentication);
            }
            if has_secret || mcp_bearer {
                let missing =
                    (has_secret && secret_unbound) || (!has_secret && mcp_bearer && no_secret);
                return Some(if missing {
                    CredentialsStatus::NeedsAuthentication
                } else {
                    CredentialsStatus::Ok
                });
            }
            return None;
        }
        // A connection exists but we don't know its scopes — benefit of the
        // doubt (same as the call-time gate). Classify as Ok for OAuth.
        ScopeKnowledge::Unknown => {
            return if has_oauth {
                Some(CredentialsStatus::Ok)
            } else {
                None
            };
        }
        ScopeKnowledge::Known(list) => list,
    };

    if !has_oauth {
        return None;
    }

    // MCP-oauth templates carry their scopes at the service level, not per
    // action, so the per-action loop below is a no-op that would always report
    // `Ok`. Check the mcp scopes against the connection's granted set directly
    // (all-or-nothing — there's one scope set, no per-action granularity) so
    // the backend status agrees with the dashboard's missing-scope warning.
    if let Some(McpAuth::OAuth {
        scopes: mcp_scopes, ..
    }) = template.mcp.as_ref().map(|m| &m.auth)
    {
        if mcp_scopes.is_empty() {
            return Some(CredentialsStatus::Ok);
        }
        let granted: std::collections::HashSet<&str> =
            granted_list.iter().map(String::as_str).collect();
        let all_covered = mcp_scopes.iter().all(|s| granted.contains(s.as_str()));
        return Some(if all_covered {
            CredentialsStatus::Ok
        } else {
            CredentialsStatus::NeedsReconnect
        });
    }

    let mut any_ok = false;
    let mut any_gap = false;
    for action in template.actions.values() {
        match action_scope_coverage(action, ScopeKnowledge::Known(granted_list)).0 {
            ScopeCoverage::Covered => any_ok = true,
            ScopeCoverage::NeedsReconnect => any_gap = true,
            // Known scopes never yield Unknown.
            ScopeCoverage::Unknown => {}
        }
    }

    Some(match (any_ok, any_gap) {
        (false, true) => CredentialsStatus::NeedsReconnect,
        (true, true) => CredentialsStatus::PartiallyDegraded,
        _ => CredentialsStatus::Ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::platform_services::test_fixtures::*;

    #[test]
    fn mcp_oauth_credentials_status_checks_service_level_scopes() {
        let def = mcp_oauth_template("slack", &["chat:write", "channels:read"]);
        // No connection → must connect.
        assert_eq!(
            derive_credentials_status(
                &def,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
        // Connection covers every mcp scope → Ok.
        let full = ["chat:write".to_string(), "channels:read".to_string()];
        assert_eq!(
            derive_credentials_status(
                &def,
                ScopeKnowledge::Known(&full),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
        // Connection missing a scope → NeedsReconnect (not a false Ok from the
        // per-action loop, which is empty for MCP tools).
        let partial = ["channels:read".to_string()];
        assert_eq!(
            derive_credentials_status(
                &def,
                ScopeKnowledge::Known(&partial),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsReconnect)
        );
        // Unknown granted scopes → benefit of the doubt (Ok), matching the gate.
        assert_eq!(
            derive_credentials_status(&def, ScopeKnowledge::Unknown, &CredentialsMap::new(), None),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn needs_authentication_when_oauth_template_has_no_connection() {
        let tpl = oauth_template(vec![("a", vec!["s1"])]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    #[test]
    fn none_when_template_has_no_auth_and_no_connection() {
        let tpl = ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        };
        assert!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            )
            .is_none()
        );
    }

    #[test]
    fn ok_when_connection_covers_every_action() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["s1", "s2"]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn ok_when_template_declares_no_required_scopes() {
        let tpl = oauth_template(vec![("a", vec![]), ("b", vec![])]);
        let granted = scopes(&[]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn ok_when_connection_scopes_unknown_benefit_of_the_doubt() {
        // An imported connection with no declared scopes classifies as Ok, not
        // degraded — mirrors the call-time scope-gate giving it the benefit of
        // the doubt.
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        assert_eq!(
            derive_credentials_status(&tpl, ScopeKnowledge::Unknown, &CredentialsMap::new(), None),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn partially_degraded_when_some_actions_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["s1"]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::PartiallyDegraded)
        );
    }

    #[test]
    fn needs_reconnect_when_no_action_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["other"]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsReconnect)
        );
    }

    #[test]
    fn ok_when_mcp_bearer_has_secret_and_no_connection() {
        let tpl = mcp_bearer_template(None);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                Some("whatsapp_mcp_token")
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn needs_authentication_when_mcp_bearer_has_no_secret_and_no_connection() {
        let tpl = mcp_bearer_template(None);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                Some("")
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    #[test]
    fn ok_when_secret_template_has_secret_and_no_connection() {
        let tpl = secret_template();
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                Some("my_api_key")
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    /// A template whose only secret scheme resolves an org-vault default needs
    /// no instance binding — the old `.any(ApiKey)` predicate (pre-rename) misreported it
    /// as NeedsAuthentication forever.
    #[test]
    fn ok_when_all_secret_schemes_are_org_source_and_nothing_bound() {
        let mut tpl = secret_template();
        if let ServiceAuth::Secret { secret_source, .. } = &mut tpl.auth[0] {
            *secret_source = overslash_core::types::SecretSource::Org;
        }
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn credentials_map_binding_satisfies_instance_scheme_without_scalar() {
        let tpl = dual_scheme_template();
        let bound = CredentialsMap::from([("mailbox".to_string(), "my_login".to_string())]);
        assert_eq!(
            derive_credentials_status(&tpl, ScopeKnowledge::NoConnection, &bound, None),
            Some(CredentialsStatus::Ok)
        );
        // Binding only the optional org slot leaves the required mailbox slot
        // empty → still needs authentication.
        let gateway_only = CredentialsMap::from([("gateway".to_string(), "gw".to_string())]);
        assert_eq!(
            derive_credentials_status(&tpl, ScopeKnowledge::NoConnection, &gateway_only, None),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    fn scoped_action(required: &[&str]) -> ServiceAction {
        let tpl = oauth_template(vec![("a", required.to_vec())]);
        tpl.actions.get("a").unwrap().clone()
    }

    #[test]
    fn coverage_covered_when_all_required_granted() {
        let action = scoped_action(&["s1", "s2"]);
        let granted = scopes(&["s1", "s2", "s3"]);
        let (cov, missing) = action_scope_coverage(&action, ScopeKnowledge::Known(&granted));
        assert_eq!(cov, ScopeCoverage::Covered);
        assert!(missing.is_empty());
    }

    #[test]
    fn coverage_needs_reconnect_lists_only_missing() {
        let action = scoped_action(&["s1", "s2"]);
        let granted = scopes(&["s1"]);
        let (cov, missing) = action_scope_coverage(&action, ScopeKnowledge::Known(&granted));
        assert_eq!(cov, ScopeCoverage::NeedsReconnect);
        assert_eq!(missing, vec!["s2".to_string()]);
    }

    #[test]
    fn coverage_unknown_for_unrecorded_or_absent_connection() {
        let action = scoped_action(&["s1"]);
        assert_eq!(
            action_scope_coverage(&action, ScopeKnowledge::Unknown).0,
            ScopeCoverage::Unknown
        );
        assert_eq!(
            action_scope_coverage(&action, ScopeKnowledge::NoConnection).0,
            ScopeCoverage::Unknown
        );
    }

    #[test]
    fn coverage_covered_when_action_requires_no_scopes() {
        let action = scoped_action(&[]);
        // Even with an unrecorded grant, an action that declares no scopes is
        // always covered.
        let (cov, missing) = action_scope_coverage(&action, ScopeKnowledge::Unknown);
        assert_eq!(cov, ScopeCoverage::Covered);
        assert!(missing.is_empty());
    }
}
