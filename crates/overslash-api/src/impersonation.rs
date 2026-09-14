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
//! A companion `X-Overslash-As-Name` header carries the *display name* of the
//! user root, which the target path itself cannot express: an email identifies
//! a person but does not say what to call them, so without it a provisioned
//! member is named after their email local-part. Agents need no equivalent —
//! for them the path segment already **is** the name.
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

/// What an `X-Overslash-As` value resolved to.
pub struct ResolvedTarget {
    /// The effective identity to act as — the leaf of the path.
    pub identity_id: Uuid,
    /// The kind of the effective identity (`user`, `agent`, `sub_agent`).
    ///
    /// Carried out so the extractor can stamp `last_active_at` on a
    /// `sub_agent` target without a second lookup: impersonation is the one
    /// authentication route that produces activity on an identity nobody
    /// holds a key for, and the idle sweep reaps whatever it cannot see.
    pub kind: String,
    /// The root user whose display name the caller may still refresh, set only
    /// when a name was supplied for a user root that already existed.
    ///
    /// The rename is handed back rather than done here on purpose: it is a
    /// write to a row that was *not* created by this request, so it must not
    /// land until the extractor's ACL cap has agreed the caller may act as this
    /// target at all. (Provisioning runs before the cap, as it always has — a
    /// row that did not exist a moment ago leaks nothing.)
    pub renameable_root: Option<Uuid>,
}

/// Resolve the `X-Overslash-As` value `raw` into the effective identity to act
/// as, provisioning any missing user / agent levels along the way.
///
/// `display_name` is the parsed `X-Overslash-As-Name` value. It names the user
/// root only: a freshly provisioned user is created with it instead of a label
/// guessed from their email, and an existing root is reported back as
/// [`ResolvedTarget::renameable_root`] for the caller to apply post-cap. Agent
/// segments ignore it — their name is the path segment.
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
    display_name: Option<&str>,
    caller_identity_id: Uuid,
    ip: Option<&str>,
) -> Result<ResolvedTarget, AppError> {
    let target =
        parse_target_path(raw).map_err(|e| AppError::BadRequest(format!("x-overslash-as: {e}")))?;

    // Root: an explicit id resolves directly (and must be a live identity);
    // an email resolves-or-creates a user in this org.
    let (mut current, mut path_label, root_created) = match target.root {
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
            (ident, id.to_string(), false)
        }
        TargetRoot::Email(email) => {
            // A supplied name is the whole point of the header; the derived
            // one is what we fall back to when nobody told us better.
            let name_source = if display_name.is_some() {
                "header"
            } else {
                "email"
            };
            let (ident, created) = scope
                .get_or_create_user_identity_by_email(
                    email,
                    display_name.unwrap_or_else(|| user_name_from_email(email)),
                    json!({ "provisioned_by": "impersonation", "name_source": name_source }),
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
                log_provisioned(
                    scope,
                    caller_identity_id,
                    ip,
                    email,
                    &ident.id,
                    Some(name_source),
                )
                .await;
            }
            (ident, email.to_string(), created)
        }
    };

    // A path is only meaningful under a user — agents hang off the user root.
    if !target.agents.is_empty() && current.kind != "user" {
        return Err(AppError::BadRequest(
            "an agent path can only be resolved under a user identity".into(),
        ));
    }

    // The display name belongs to the person at the root. Aimed at a UUID that
    // turns out to be an agent it has no meaning, and silently dropping it
    // would let a caller believe a rename happened. Say so instead.
    if display_name.is_some() && current.kind != "user" {
        return Err(AppError::BadRequest(
            "x-overslash-as-name applies to a user identity; this target is not one".into(),
        ));
    }

    // A root that already existed may still be renameable — the repo decides,
    // and the extractor applies it once the ACL cap has passed.
    let renameable_root = match (display_name, root_created) {
        (Some(_), false) if current.kind == "user" => Some(current.id),
        _ => None,
    };

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
            log_provisioned(scope, caller_identity_id, ip, &path_label, &child.id, None).await;
        }
        current = child;
    }

    Ok(ResolvedTarget {
        identity_id: current.id,
        kind: current.kind,
        renameable_root,
    })
}

/// Apply a display name to an already-existing user root, after the caller has
/// cleared the ACL cap. A no-op when the row is adopted, an admin, or already
/// carries this name — see `rename_if_unadopted` for why each of those is
/// excluded. Best-effort audit, like provisioning: the rename itself is the
/// request's effect, and a failed log must not undo it.
pub async fn apply_display_name(
    scope: &OrgScope,
    root_id: Uuid,
    display_name: &str,
    caller_identity_id: Uuid,
    ip: Option<&str>,
) -> Result<(), AppError> {
    let Some(previous) = scope
        .rename_unadopted_user_identity(root_id, display_name)
        .await
        .map_err(db_err)?
    else {
        return Ok(());
    };

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: Some(caller_identity_id),
            action: "identity.updated",
            resource_type: Some("identity"),
            resource_id: Some(root_id),
            detail: json!({
                "via": "impersonation",
                "field": "name",
                "from": previous,
                "to": display_name,
            }),
            description: None,
            ip_address: ip,
        })
        .await;
    Ok(())
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
    name_source: Option<&str>,
) {
    let mut detail = json!({ "via": "impersonation", "path": path });
    // Only user roots have a name to source; agents are named by their segment.
    if let Some(source) = name_source {
        detail["name_source"] = json!(source);
    }
    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: Some(caller_identity_id),
            action: "identity.provisioned",
            resource_type: Some("identity"),
            resource_id: Some(*provisioned_id),
            detail,
            description: None,
            ip_address: ip,
        })
        .await;
}

/// Derive a human-ish display name from an email local-part for a freshly
/// provisioned user. The email itself remains the identifier; this is only a
/// label, refreshed from the IdP profile at first real sign-in.
///
/// The fallback of last resort: a caller that knows the real name should send
/// `X-Overslash-As-Name` rather than leave the org looking at `alice`.
fn user_name_from_email(email: &str) -> &str {
    let local = email.split('@').next().unwrap_or(email);
    if local.is_empty() { email } else { local }
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Internal(format!("db error: {e}"))
}
