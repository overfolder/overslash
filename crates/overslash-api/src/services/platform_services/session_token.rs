//! The bearer Overslash mints for an `auth.generate` MCP instance — the
//! session token a platform-hosted multi-tenant gateway keys its tenant on —
//! and its release when the instance goes away.

use overslash_core::types::SecretPath;
use overslash_db::repos::service_instance::ServiceInstanceRow;
use uuid::Uuid;

use super::PlatformCallContext;
use crate::error::AppError;
use overslash_db::OrgScope;

const SESSION_INFIX: &str = "_session_";
/// Hex digits of the random part: four bytes.
const SESSION_SUFFIX_LEN: usize = 8;

/// The template key as it appears in a minted name: lowercase alphanumerics,
/// everything else `_`.
fn session_stem(template_key: &str) -> String {
    template_key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Whether `name` has the exact shape [`mint_session_token`] gives a token for
/// `template_key`. A name the owner chose can match only by deliberately
/// imitating it, and even then [`release_session_token`] leaves it alone while
/// any other instance is bound to it.
fn is_minted_name(template_key: &str, name: &str) -> bool {
    name.strip_prefix(&session_stem(template_key))
        .and_then(|rest| rest.strip_prefix(SESSION_INFIX))
        .is_some_and(|hex| {
            hex.len() == SESSION_SUFFIX_LEN
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Mint a random bearer for an `auth.generate` MCP instance and store it in
/// the instance owner's vault (the org vault for an org-level instance), the
/// same place a pasted token would live — so it rotates, versions and audits
/// like any other instance secret, and the user never handles it.
///
/// The name is `<template>_session_<random>`, never a name the owner chose, so
/// it cannot overwrite an existing secret; a collision on the random part is
/// retried rather than reused.
pub(super) async fn mint_session_token(
    ctx: &PlatformCallContext,
    scope: &OrgScope,
    owner_identity_id: Option<Uuid>,
    template_key: &str,
) -> Result<overslash_core::types::SecretPath, AppError> {
    use rand::RngExt as _;

    let ns = overslash_core::types::SecretNamespace::from_owner(owner_identity_id);
    let stem = session_stem(template_key);
    for _ in 0..4 {
        let mut suffix = [0u8; 4];
        rand::rng().fill(&mut suffix);
        let name = format!("{stem}{SESSION_INFIX}{}", hex::encode(suffix));
        let path = ns.path(name);
        if scope.get_secret(&path).await?.is_some() {
            continue;
        }
        let mut token = [0u8; 32];
        rand::rng().fill(&mut token);
        let token =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token);
        let encrypted = overslash_core::crypto::encrypt(&ctx.config.keyring()?, token.as_bytes())?;
        let (secret, _) = scope
            .put_secret(&path, &encrypted, ctx.identity_id, None)
            .await?;
        let _ = scope
            .log_audit(overslash_db::repos::audit::AuditEntry {
                org_id: ctx.org_id,
                identity_id: ctx.identity_id,
                action: "secret.put",
                resource_type: Some("secret"),
                resource_id: None,
                detail: serde_json::json!({
                    "name": &secret.name,
                    "version": secret.current_version,
                    "owner_identity_id": secret.owner_identity_id,
                    "path": path.to_canonical(),
                    "generated": true,
                }),
                description: None,
                ip_address: None,
            })
            .await;
        return Ok(path);
    }
    Err(AppError::Internal(
        "could not find a free name for the generated session token".into(),
    ))
}

/// Soft-delete the token minted for `instance`, which has just been deleted.
///
/// The token was made for this one instance and is useless without it: left
/// behind it is a credential nobody can see a reason for, still able to open
/// the gateway session it names. Only a binding with the minted shape is
/// touched, and only while no other instance is bound to it — so a secret the
/// owner chose, or one they deliberately re-bound elsewhere, survives.
///
/// Best-effort, like the connection cleanup beside it: the instance is
/// already gone, so a failure here is logged and never fails the delete.
/// Returns whether a token was released.
pub async fn release_session_token(
    scope: &OrgScope,
    instance: &ServiceInstanceRow,
    actor_identity_id: Option<Uuid>,
    ip_address: Option<&str>,
) -> bool {
    let Some(path) = minted_binding(instance) else {
        return false;
    };
    match try_release(scope, &path).await {
        Ok(released) => {
            if released {
                let _ = scope
                    .log_audit(overslash_db::repos::audit::AuditEntry {
                        org_id: scope.org_id(),
                        identity_id: actor_identity_id,
                        action: "secret.deleted",
                        resource_type: Some("secret"),
                        resource_id: None,
                        detail: serde_json::json!({
                            "name": &path.name,
                            "path": path.to_canonical(),
                            "generated": true,
                            "service_instance_id": instance.id,
                        }),
                        description: None,
                        ip_address,
                    })
                    .await;
            }
            released
        }
        Err(e) => {
            tracing::warn!(
                service_instance_id = %instance.id,
                error = %e,
                "service delete: minted session token cleanup failed"
            );
            false
        }
    }
}

/// The instance's bearer binding, if it is one [`mint_session_token`] wrote.
fn minted_binding(instance: &ServiceInstanceRow) -> Option<SecretPath> {
    let stored = instance.secret_name.as_deref()?;
    let path = crate::services::secret_paths::readable_instance_binding(
        instance.owner_identity_id,
        stored,
    )?;
    is_minted_name(&instance.template_key, &path.name).then_some(path)
}

async fn try_release(scope: &OrgScope, path: &SecretPath) -> Result<bool, sqlx::Error> {
    if !scope.list_services_using_secret(path).await?.is_empty() {
        return Ok(false);
    }
    scope.soft_delete_secret(path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_minted_shape_is_recognised() {
        assert!(is_minted_name("whatsapp", "whatsapp_session_0a1b2c3d"));
        assert!(is_minted_name("my-gw", "my_gw_session_deadbeef"));
        // Another template's token, a name the owner chose, a wrong length,
        // uppercase hex: none of them is ours to delete.
        assert!(!is_minted_name("telegram", "whatsapp_session_0a1b2c3d"));
        assert!(!is_minted_name("whatsapp", "whatsapp_token"));
        assert!(!is_minted_name("whatsapp", "whatsapp_session_0a1b2c3"));
        assert!(!is_minted_name("whatsapp", "whatsapp_session_0a1b2c3d4"));
        assert!(!is_minted_name("whatsapp", "whatsapp_session_0A1B2C3D"));
    }
}
