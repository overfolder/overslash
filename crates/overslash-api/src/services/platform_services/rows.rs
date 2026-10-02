//! Row → response-shape mappers.

use super::*;
use crate::services::secret_paths::relative_to_instance;

/// Bindings as the API shows them — see [`relative_to_instance`]. `viewer`
/// is the reading caller's own vault (its ceiling user), the home vault of an
/// org-level instance.
fn relative_credentials(row: &ServiceInstanceRow, viewer: Option<Uuid>) -> CredentialsMap {
    row.credentials
        .0
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                relative_to_instance(row.owner_identity_id, viewer, v),
            )
        })
        .collect()
}

fn relative_secret_name(row: &ServiceInstanceRow, viewer: Option<Uuid>) -> Option<String> {
    row.secret_name
        .as_deref()
        .map(|v| relative_to_instance(row.owner_identity_id, viewer, v))
}

/// `viewer`: the reading caller's ceiling user, `None` for an org-level key.
pub fn row_to_summary(
    row: ServiceInstanceRow,
    groups: Vec<ServiceGroupRef>,
    viewer: Option<Uuid>,
) -> ServiceInstanceSummary {
    let (secret_name, credentials) = (
        relative_secret_name(&row, viewer),
        relative_credentials(&row, viewer),
    );
    ServiceInstanceSummary {
        auth_mode: row.auth_mode.clone(),
        // Set by the caller, which is where the resolved template is in hand —
        // same as `credentials_status`.
        icon_url: None,
        id: row.id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        status: row.status,
        is_system: row.is_system,
        owner_identity_id: row.owner_identity_id,
        connection_id: row.connection_id,
        secret_name,
        credentials,
        config: row.config.0,
        url: row.url,
        use_default_connection: row.use_default_connection,
        groups,
        credentials_status: None,
        test_action: None,
    }
}

/// `viewer`: the reading caller's ceiling user, `None` for an org-level key.
pub fn row_to_detail(row: ServiceInstanceRow, viewer: Option<Uuid>) -> ServiceInstanceDetail {
    let (secret_name, credentials) = (
        relative_secret_name(&row, viewer),
        relative_credentials(&row, viewer),
    );
    ServiceInstanceDetail {
        auth_mode: row.auth_mode.clone(),
        icon_url: None,
        id: row.id,
        org_id: row.org_id,
        owner_identity_id: row.owner_identity_id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        template_id: row.template_id,
        connection_id: row.connection_id,
        secret_name,
        credentials,
        config: row.config.0,
        url: row.url,
        use_default_connection: row.use_default_connection,
        status: row.status,
        is_system: row.is_system,
        created_at: fmt_time(row.created_at),
        updated_at: fmt_time(row.updated_at),
        discovered_at: row.discovered_at.map(fmt_time),
        credentials_status: None,
        test_action: None,
        connect: None,
        setup: None,
    }
}
