//! Row → response-shape mappers.

use super::*;

pub fn row_to_summary(
    row: ServiceInstanceRow,
    groups: Vec<ServiceGroupRef>,
) -> ServiceInstanceSummary {
    ServiceInstanceSummary {
        id: row.id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        status: row.status,
        is_system: row.is_system,
        owner_identity_id: row.owner_identity_id,
        connection_id: row.connection_id,
        secret_name: row.secret_name,
        credentials: row.credentials.0,
        config: row.config.0,
        url: row.url,
        use_default_connection: row.use_default_connection,
        groups,
        credentials_status: None,
    }
}

pub fn row_to_detail(row: ServiceInstanceRow) -> ServiceInstanceDetail {
    ServiceInstanceDetail {
        id: row.id,
        org_id: row.org_id,
        owner_identity_id: row.owner_identity_id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        template_id: row.template_id,
        connection_id: row.connection_id,
        secret_name: row.secret_name,
        credentials: row.credentials.0,
        config: row.config.0,
        url: row.url,
        use_default_connection: row.use_default_connection,
        status: row.status,
        is_system: row.is_system,
        created_at: fmt_time(row.created_at),
        updated_at: fmt_time(row.updated_at),
        discovered_at: row.discovered_at.map(fmt_time),
        credentials_status: None,
        connect: None,
    }
}
