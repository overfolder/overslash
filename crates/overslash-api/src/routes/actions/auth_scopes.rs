//! OAuth scope gating: the fail-fast `required_scopes` check and the
//! metadata-scope denial sniffer.
//!
//! Split out of `auth.rs`.

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{AppState, error::AppError, services::platform_connections};

use super::auth::org_is_headless;

/// Fail-fast scope gate: before the outgoing request is built, compare the
/// connection's granted scopes against what this action declares. When a
/// template doesn't declare `required_scopes`, returns `Ok(())` — preserves
/// today's behavior for templates that haven't adopted the field.
///
/// Returns `AppError::MissingScopes`, rendered as 403 with the typed
/// `missing_scopes` envelope (`{ error, missing, connection_id, upgrade_url,
/// auth_url? }`). The `upgrade_url` is the raw REST endpoint white-label
/// callers can POST to; `auth_url` is the chat-deliverable gated link agents
/// should hand to the user.
pub(super) async fn check_required_scopes(
    state: &AppState,
    scope: &OrgScope,
    // Auto-resolved connections are read at the owner identity (D22), matching
    // what `resolve_service_auth` will actually use. Explicit instance→
    // connection bindings still resolve org-scoped via `scope.get_connection`.
    owner_identity_id: Uuid,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    svc: &overslash_core::types::ServiceDefinition,
    action: &overslash_core::types::ServiceAction,
    return_url_hint: Option<&str>,
) -> Result<(), AppError> {
    if action.required_scopes.is_empty() {
        return Ok(());
    }

    // Find the OAuth service-auth entry; a template without OAuth can't have
    // its scopes checked here.
    let provider = svc.auth.iter().find_map(|a| match a {
        overslash_core::types::ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
        _ => None,
    });
    let Some(provider) = provider else {
        return Ok(());
    };

    let org_id = scope.org_id();

    // Resolve the connection the exec path would actually use — instance's
    // explicit binding takes precedence, else the owner's default connection.
    // Shared with the exec/resync OAuth-bearer path so the gate and the token
    // are always read from the same connection.
    let connection = super::mcp_resolve::resolve_instance_connection(
        scope,
        owner_identity_id,
        instance,
        &provider,
    )
    .await?;

    let Some(connection) = connection else {
        // Fall through — auth resolution will report the missing connection
        // in its own way. The scope gate is only meaningful when a
        // connection exists.
        return Ok(());
    };

    // Unknown granted scopes (a token import that didn't declare them) get the
    // benefit of the doubt — Overslash can't know what the token covers, so it
    // doesn't pre-emptively 403; a genuine scope shortfall still surfaces as the
    // upstream's own error. A known set (orchestrated connections always record
    // one) is gated precisely.
    let Some(granted_scopes) = connection.scopes.as_deref() else {
        return Ok(());
    };
    let granted: std::collections::HashSet<&str> =
        granted_scopes.iter().map(String::as_str).collect();
    let missing: Vec<String> = action
        .required_scopes
        .iter()
        .filter(|s| !granted.contains(s.as_str()))
        .cloned()
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    // Headless (white-label) org: omit both the gated `auth_url` and the
    // `upgrade_url` — the org's end users can't open either, and minting an
    // upgrade flow would leave a stray flow row. The integration broadens the
    // grant against its own client and re-imports the connection.
    if org_is_headless(scope.db(), org_id).await {
        return Err(AppError::MissingScopes {
            connection_id: connection.id,
            required: action.required_scopes.clone(),
            missing,
            upgrade_url: None,
            auth_url: None,
            short: None,
            provider: Some(connection.provider_key.clone()),
            account_email: connection.account_email.clone(),
            headless: true,
        });
    }

    // Mint a chat-deliverable gated `/connect-authorize` URL that, when
    // consumed, runs an incremental-scope OAuth flow against the existing
    // connection (the minted flow row's `upgrade_connection_id` points at
    // `connection.id`; the callback reads it back from the row). The legacy
    // `upgrade_url` field — pointing at the raw REST endpoint
    // `/v1/connections/{id}/upgrade_scopes` — is preserved alongside for
    // white-label callers that drive the API directly. Agents should use
    // `auth_url`.
    //
    // If the mint fails (DB hiccup, provider-key lookup), don't break the
    // missing_scopes contract by surfacing the mint error: log it and omit
    // `auth_url` from the body. The dashboard / REST clients will fall
    // back to `upgrade_url`, and the client still gets the correct 403
    // missing_scopes shape.
    let (auth_url, short) = match platform_connections::mint_upgrade_auth_url(
        state,
        scope.org_id(),
        owner_identity_id,
        &connection,
        &missing,
        return_url_hint,
    )
    .await
    {
        Ok(urls) => (Some(urls.auth_url), urls.short),
        Err(e) => {
            tracing::error!(
                "missing_scopes: failed to mint upgrade auth url for connection {}: {e}",
                connection.id
            );
            (None, None)
        }
    };
    let upgrade_url = format!(
        "{}/v1/connections/{}/upgrade_scopes",
        state.config.public_url.trim_end_matches('/'),
        connection.id
    );
    Err(AppError::MissingScopes {
        connection_id: connection.id,
        required: action.required_scopes.clone(),
        missing,
        upgrade_url: Some(upgrade_url),
        auth_url,
        short,
        provider: Some(connection.provider_key.clone()),
        account_email: connection.account_email.clone(),
        headless: false,
    })
}

/// Whether an upstream response body is Google's "metadata scope" denial:
/// a `PERMISSION_DENIED` (HTTP 403) whose message is
/// `"Metadata scope does not support 'q' parameter"` (or any other metadata
/// message). This means the *injected access token was metadata-only* even
/// though the connection's recorded scopes claimed a broader grant like
/// `gmail.readonly` — the exact divergence from connection `85844f1a`.
///
/// We match on the stable substring `"Metadata scope does not support"` rather
/// than the full message so a change to the offending parameter name (`'q'` vs
/// something else) doesn't slip past. Only inspects 403 responses.
pub(crate) fn is_metadata_scope_denial(status_code: u16, body: &str) -> bool {
    status_code == 403 && body.contains("Metadata scope does not support")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_scope_denial_detected_only_on_403() {
        let body = r#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Metadata scope does not support 'q' parameter"}}"#;
        assert!(is_metadata_scope_denial(403, body));
        // Same body on a non-403 status is not the metadata-scope signal.
        assert!(!is_metadata_scope_denial(200, body));
        assert!(!is_metadata_scope_denial(500, body));
    }

    #[test]
    fn metadata_scope_denial_ignores_unrelated_403() {
        let body = r#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Request had insufficient authentication scopes."}}"#;
        assert!(!is_metadata_scope_denial(403, body));
    }
}
