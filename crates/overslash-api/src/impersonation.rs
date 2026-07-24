//! Resolution of the `X-Overslash-As` header into an effective identity id.
//!
//! An API key that carries the `"impersonate"` scope may act as another
//! identity in its own org. The header names that identity in one of three
//! forms (see [`overslash_core::identity_path::parse_target_path`]):
//!
//! ```text
//! X-Overslash-As: <uuid>                              // resolve, never create
//! X-Overslash-As: alice@acme.com                       // user, created if unknown
//! X-Overslash-As: alice@acme.com/henry/researcher      // …plus a path of agents beneath her
//! ```
//!
//! The value splits on `/`: the first segment is the user (a UUID or an
//! email — neither can contain `/`), and each remaining segment is an agent
//! name resolved, then created if absent, one level at a time.
//!
//! Everything created here is deliberately unprivileged: user identities are
//! bare org members, agents never inherit permissions. An impersonation
//! header can widen *who* the caller acts as (bounded by the ACL cap the
//! extractor applies afterwards) but never manufacture new authority.

use overslash_core::identity_path::{TargetRoot, parse_target_path};
use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use serde_json::json;
use uuid::Uuid;

use crate::error::AppError;

/// Resolve the `X-Overslash-As` value `raw` into the effective identity id to
/// act as, provisioning any missing user / agent levels along the way.
///
/// `caller_identity_id` is the impersonating key's own identity; it is
/// recorded on any `identity.provisioned` audit rows so the provenance of an
/// auto-created identity survives. `ip` labels those rows.
///
/// This does **not** apply the caller-vs-target ACL cap — the extractor does
/// that on the returned id, unchanged, so the cap sees the final effective
/// identity whether it was named directly or created here.
pub async fn resolve_target(
    scope: &OrgScope,
    raw: &str,
    caller_identity_id: Uuid,
    ip: Option<&str>,
) -> Result<Uuid, AppError> {
    let target =
        parse_target_path(raw).map_err(|e| AppError::BadRequest(format!("x-overslash-as: {e}")))?;

    // Root: an explicit id resolves directly (and must be a live identity);
    // an email resolves-or-creates a user in this org.
    let (mut current, mut path_label) = match target.root {
        TargetRoot::Id(id) => {
            let ident = scope
                .get_identity(id)
                .await
                .map_err(db_err)?
                .ok_or_else(|| AppError::NotFound("impersonation target not found".into()))?;
            if ident.archived_at.is_some() {
                return Err(AppError::Forbidden(
                    "impersonation target is archived".into(),
                ));
            }
            (ident, id.to_string())
        }
        TargetRoot::Email(email) => {
            let (ident, created) = scope
                .get_or_create_user_identity_by_email(
                    email,
                    user_name_from_email(email),
                    json!({ "provisioned_by": "impersonation" }),
                )
                .await
                .map_err(db_err)?;
            if created {
                // New members get Everyone + Myself just like every other
                // user-identity creation path (see `bootstrap_user_in_org`).
                overslash_db::repos::org_bootstrap::bootstrap_user_in_org(
                    scope.db(),
                    scope.org_id(),
                    ident.id,
                )
                .await
                .map_err(db_err)?;
                log_provisioned(scope, caller_identity_id, ip, email, &ident.id).await;
            }
            (ident, email.to_string())
        }
    };

    // A path is only meaningful under a user — agents hang off the user root.
    if !target.agents.is_empty() && current.kind != "user" {
        return Err(AppError::BadRequest(
            "an agent path can only be resolved under a user identity".into(),
        ));
    }

    // The user is the owner of every agent beneath it (`on_behalf_of`
    // semantics); `owner_id` stays fixed to the user for the whole descent.
    let owner_id = current.id;

    for (i, name) in target.agents.iter().enumerate() {
        // First level below the user is an agent; deeper levels are
        // sub-agents (matching the User → Agent → SubAgent hierarchy and the
        // kind CHECK on `identities`).
        let kind = if i == 0 { "agent" } else { "sub_agent" };

        let (child, created) = scope
            .get_or_create_identity_child(
                current.id,
                name,
                kind,
                current.depth + 1,
                owner_id,
                json!({ "provisioned_by": "impersonation" }),
            )
            .await
            .map_err(db_err)?;

        // A child row can only be archived if it pre-existed — creation never
        // yields one. Refuse to act as an archived agent rather than silently
        // minting a live twin beside it.
        if child.archived_at.is_some() {
            return Err(AppError::Forbidden(
                "impersonation target is archived".into(),
            ));
        }

        path_label.push('/');
        path_label.push_str(name);
        if created {
            log_provisioned(scope, caller_identity_id, ip, &path_label, &child.id).await;
        }
        current = child;
    }

    Ok(current.id)
}

/// Best-effort `identity.provisioned` audit row for an auto-created identity.
/// Logged under the impersonating key's identity so "who caused this" is
/// answerable; failure to log never fails the request.
async fn log_provisioned(
    scope: &OrgScope,
    caller_identity_id: Uuid,
    ip: Option<&str>,
    path: &str,
    provisioned_id: &Uuid,
) {
    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: Some(caller_identity_id),
            action: "identity.provisioned",
            resource_type: Some("identity"),
            resource_id: Some(*provisioned_id),
            detail: json!({ "via": "impersonation", "path": path }),
            description: None,
            ip_address: ip,
        })
        .await;
}

/// Derive a human-ish display name from an email local-part for a freshly
/// provisioned user. The email itself remains the identifier; this is only a
/// label, refreshed from the IdP profile at first real sign-in.
fn user_name_from_email(email: &str) -> &str {
    let local = email.split('@').next().unwrap_or(email);
    if local.is_empty() { email } else { local }
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Internal(format!("db error: {e}"))
}
