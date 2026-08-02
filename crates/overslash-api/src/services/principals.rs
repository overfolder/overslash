//! Resolve the *principal* of a service — the account an instance speaks for —
//! for the surfaces that want to name it alongside a service.
//!
//! A principal is the bound (or owner-provider) OAuth connection's
//! `account_email`, or, for a secret-based instance with no connection to ask,
//! the value of the template's `identity: true` config var (email's
//! `mailbox_user`). This is the same notion the discovery surface reports as an
//! instance's `account_email` (`routes/search.rs`), lifted here so the
//! permission-rule describer can prefix rules like "Email (ops@acme.com) · …".

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use overslash_core::registry::ServiceRegistry;
use overslash_db::scopes::{OrgScope, UserScope};

use crate::error::Result;
use crate::services::group_ceiling;
use crate::services::platform_services::template_oauth_provider;

/// The last step of the principal precedence, in isolation: a secret-based
/// instance's identity-bearing config var (email's `mailbox_user`).
///
/// Pure — no queries — so the action call path can reach for it after the
/// auth resolvers came back without a connection to name. Steps 1 and 2 of the
/// precedence both need a connection row, and on that path the resolvers have
/// already loaded (or declined to load) one.
pub fn instance_config_principal(
    def: &overslash_core::types::ServiceDefinition,
    instance: &overslash_db::repos::service_instance::ServiceInstanceRow,
) -> Option<String> {
    let key = def.identity_config_key()?;
    instance.config.0.get(key).cloned()
}

/// Distinct principals per service **template key**, across the active instances
/// the given identity can use.
///
/// Only registry-known templates are resolved — the describer only prefixes a
/// rule when it can name the service, so an org-custom template absent from the
/// registry never contributes a principal here either.
///
/// A template maps to a set because an owner can hold several instances of one
/// service (three mailboxes, two GitHub accounts). Callers that want to show a
/// principal only when it is unambiguous check `set.len() == 1`.
pub async fn resolve_service_principals(
    scope: &OrgScope,
    registry: &ServiceRegistry,
    target_identity_id: Uuid,
) -> Result<HashMap<String, HashSet<String>>> {
    // Same owner resolution the exec/ceiling path uses: an agent's instances
    // live at its owner user (on_behalf_of), a user's at itself.
    let ceiling_user_id = group_ceiling::resolve_ceiling_user_id(scope, target_identity_id).await?;

    let active: Vec<_> = scope
        .list_available_service_instances(Some(target_identity_id), Some(ceiling_user_id))
        .await?
        .into_iter()
        .filter(|r| r.status == "active" && registry.get(&r.template_key).is_some())
        .collect();

    // Batch-load bound connections so we read `account_email` without an N+1.
    let connection_ids: Vec<Uuid> = active
        .iter()
        .filter_map(|r| r.connection_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let connections_by_id = scope.get_connections_by_ids(&connection_ids).await?;

    // Auto-resolved owner-provider connections, deduped by (owner, provider).
    let mut owner_provider_email: HashMap<(Uuid, String), Option<String>> = HashMap::new();

    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for r in &active {
        // Safe: `active` is filtered to registry-known templates.
        let def = match registry.get(&r.template_key) {
            Some(d) => d,
            None => continue,
        };

        // 1. A bound connection is authoritative — it is the account the call
        //    authenticates as.
        let mut principal = r
            .connection_id
            .and_then(|cid| connections_by_id.get(&cid))
            .and_then(|c| c.account_email.clone());

        // 2. Unbound OAuth instance: the owner-provider connection the exec path
        //    would pick.
        if principal.is_none() {
            if let (Some(owner), Some(provider)) =
                (r.owner_identity_id, template_oauth_provider(def))
            {
                let key = (owner, provider.to_string());
                principal = match owner_provider_email.get(&key) {
                    Some(cached) => cached.clone(),
                    None => {
                        let email = UserScope::new(scope.org_id(), owner, scope.db().clone())
                            .find_my_connection_by_provider(provider)
                            .await
                            .ok()
                            .flatten()
                            .and_then(|c| c.account_email);
                        owner_provider_email.insert(key, email.clone());
                        email
                    }
                };
            }
        }

        // 3. Secret-based instance: the identity-bearing config var.
        if principal.is_none() {
            principal = instance_config_principal(def, r);
        }

        if let Some(p) = principal {
            let p = p.trim();
            if !p.is_empty() {
                out.entry(r.template_key.clone())
                    .or_default()
                    .insert(p.to_string());
            }
        }
    }

    Ok(out)
}
