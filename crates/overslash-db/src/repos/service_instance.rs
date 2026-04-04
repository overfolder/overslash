use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ServiceInstanceRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub name: String,
    pub template_source: String,
    pub template_key: String,
    pub template_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub secret_name: Option<String>,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub struct CreateServiceInstance<'a> {
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub name: &'a str,
    pub template_source: &'a str,
    pub template_key: &'a str,
    pub template_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub secret_name: Option<&'a str>,
    pub status: &'a str,
}

pub struct UpdateServiceInstance<'a> {
    pub name: Option<&'a str>,
    pub connection_id: Option<Option<Uuid>>,
    pub secret_name: Option<Option<&'a str>>,
}

const SELECT_COLS: &str = "id, org_id, owner_identity_id, name, template_source, template_key, \
    template_id, connection_id, secret_name, status, created_at, updated_at";

pub async fn create(
    pool: &PgPool,
    input: &CreateServiceInstance<'_>,
) -> Result<ServiceInstanceRow, sqlx::Error> {
    let q = format!(
        "INSERT INTO service_instances (org_id, owner_identity_id, name, template_source, \
         template_key, template_id, connection_id, secret_name, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING {SELECT_COLS}"
    );
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(input.org_id)
        .bind(input.owner_identity_id)
        .bind(input.name)
        .bind(input.template_source)
        .bind(input.template_key)
        .bind(input.template_id)
        .bind(input.connection_id)
        .bind(input.secret_name)
        .bind(input.status)
        .fetch_one(pool)
        .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    let q = format!("SELECT {SELECT_COLS} FROM service_instances WHERE id = $1");
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Get a service instance by name within a specific scope (org or user).
pub async fn get_by_name(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    name: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    let q = if owner_identity_id.is_some() {
        format!(
            "SELECT {SELECT_COLS} FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3"
        )
    } else {
        format!(
            "SELECT {SELECT_COLS} FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $3"
        )
    };
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(org_id)
        .bind(owner_identity_id)
        .bind(name)
        .fetch_optional(pool)
        .await
}

/// Resolve a service instance by name using user-shadows-org semantics.
///
/// - `org/name` prefix forces org scope (ignores user instances)
/// - Plain `name` tries user scope first, then org scope
///
/// Only returns active instances by default (for execution). Use `get_by_name` for any status.
pub async fn resolve_by_name(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    raw_name: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    // Parse "org/" prefix
    if let Some(name) = raw_name.strip_prefix("org/") {
        // Explicit org scope
        let q = format!(
            "SELECT {SELECT_COLS} FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2 AND status = 'active'"
        );
        return sqlx::query_as::<_, ServiceInstanceRow>(&q)
            .bind(org_id)
            .bind(name)
            .fetch_optional(pool)
            .await;
    }

    // User-shadows-org: try user scope first
    if let Some(identity_id) = identity_id {
        let q = format!(
            "SELECT {SELECT_COLS} FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3 AND status = 'active'"
        );
        let user_instance = sqlx::query_as::<_, ServiceInstanceRow>(&q)
            .bind(org_id)
            .bind(identity_id)
            .bind(raw_name)
            .fetch_optional(pool)
            .await?;
        if user_instance.is_some() {
            return Ok(user_instance);
        }
    }

    // Fall through to org scope
    let q = format!(
        "SELECT {SELECT_COLS} FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2 AND status = 'active'"
    );
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(org_id)
        .bind(raw_name)
        .fetch_optional(pool)
        .await
}

/// List org-level instances.
pub async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    let q = format!(
        "SELECT {SELECT_COLS} FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NULL ORDER BY name"
    );
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(org_id)
        .fetch_all(pool)
        .await
}

/// List user-level instances for a specific identity.
pub async fn list_by_user(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    let q = format!(
        "SELECT {SELECT_COLS} FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id = $2 ORDER BY name"
    );
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(org_id)
        .bind(identity_id)
        .fetch_all(pool)
        .await
}

/// List all instances available to a caller: user's + org's.
pub async fn list_available(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    let q = format!(
        "SELECT {SELECT_COLS} FROM service_instances \
         WHERE org_id = $1 AND (owner_identity_id IS NULL OR owner_identity_id = $2) \
         ORDER BY name"
    );
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(org_id)
        .bind(identity_id)
        .fetch_all(pool)
        .await
}

pub async fn update_status(
    pool: &PgPool,
    id: Uuid,
    status: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    let q = format!(
        "UPDATE service_instances SET status = $2, updated_at = now() \
         WHERE id = $1 RETURNING {SELECT_COLS}"
    );
    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(id)
        .bind(status)
        .fetch_optional(pool)
        .await
}

pub async fn update(
    pool: &PgPool,
    id: Uuid,
    input: &UpdateServiceInstance<'_>,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    // Build dynamic update — only set fields that are Some
    let q = format!(
        "UPDATE service_instances SET \
         name = COALESCE($2, name), \
         connection_id = CASE WHEN $3 THEN $4 ELSE connection_id END, \
         secret_name = CASE WHEN $5 THEN $6 ELSE secret_name END, \
         updated_at = now() \
         WHERE id = $1 RETURNING {SELECT_COLS}"
    );
    let update_conn = input.connection_id.is_some();
    let conn_id = input.connection_id.flatten();
    let update_secret = input.secret_name.is_some();
    let secret = input.secret_name.flatten();

    sqlx::query_as::<_, ServiceInstanceRow>(&q)
        .bind(id)
        .bind(input.name)
        .bind(update_conn)
        .bind(conn_id)
        .bind(update_secret)
        .bind(secret)
        .fetch_optional(pool)
        .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM service_instances WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
