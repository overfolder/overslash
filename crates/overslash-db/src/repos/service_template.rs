use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ServiceTemplateRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub key: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub hosts: Vec<String>,
    pub auth: serde_json::Value,
    pub actions: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub struct CreateServiceTemplate<'a> {
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub key: &'a str,
    pub display_name: &'a str,
    pub description: &'a str,
    pub category: &'a str,
    pub hosts: &'a [String],
    pub auth: serde_json::Value,
    pub actions: serde_json::Value,
}

pub struct UpdateServiceTemplate<'a> {
    pub display_name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub category: Option<&'a str>,
    pub hosts: Option<&'a [String]>,
    pub auth: Option<serde_json::Value>,
    pub actions: Option<serde_json::Value>,
}

const SELECT_COLS: &str = "id, org_id, owner_identity_id, key, display_name, description, \
    category, hosts, auth, actions, created_at, updated_at";

pub async fn create(
    pool: &PgPool,
    input: &CreateServiceTemplate<'_>,
) -> Result<ServiceTemplateRow, sqlx::Error> {
    let q = format!(
        "INSERT INTO service_templates (org_id, owner_identity_id, key, display_name, description, \
         category, hosts, auth, actions) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING {SELECT_COLS}"
    );
    sqlx::query_as::<_, ServiceTemplateRow>(&q)
        .bind(input.org_id)
        .bind(input.owner_identity_id)
        .bind(input.key)
        .bind(input.display_name)
        .bind(input.description)
        .bind(input.category)
        .bind(input.hosts)
        .bind(&input.auth)
        .bind(&input.actions)
        .fetch_one(pool)
        .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    let q = format!("SELECT {SELECT_COLS} FROM service_templates WHERE id = $1");
    sqlx::query_as::<_, ServiceTemplateRow>(&q)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Look up a template by key within a specific tier (org or user).
pub async fn get_by_key(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    key: &str,
) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    let q = if owner_identity_id.is_some() {
        format!(
            "SELECT {SELECT_COLS} FROM service_templates \
             WHERE org_id = $1 AND owner_identity_id = $2 AND key = $3"
        )
    } else {
        format!(
            "SELECT {SELECT_COLS} FROM service_templates \
             WHERE org_id = $1 AND owner_identity_id IS NULL AND key = $3"
        )
    };
    sqlx::query_as::<_, ServiceTemplateRow>(&q)
        .bind(org_id)
        .bind(owner_identity_id)
        .bind(key)
        .fetch_optional(pool)
        .await
}

/// List org-level templates (owner_identity_id IS NULL).
pub async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    let q = format!(
        "SELECT {SELECT_COLS} FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id IS NULL ORDER BY key"
    );
    sqlx::query_as::<_, ServiceTemplateRow>(&q)
        .bind(org_id)
        .fetch_all(pool)
        .await
}

/// List user-level templates for a specific identity.
pub async fn list_by_user(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    let q = format!(
        "SELECT {SELECT_COLS} FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id = $2 ORDER BY key"
    );
    sqlx::query_as::<_, ServiceTemplateRow>(&q)
        .bind(org_id)
        .bind(identity_id)
        .fetch_all(pool)
        .await
}

/// List all templates available to a caller: org-level + user-level for the given identity.
pub async fn list_available(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    let q = format!(
        "SELECT {SELECT_COLS} FROM service_templates \
         WHERE org_id = $1 AND (owner_identity_id IS NULL OR owner_identity_id = $2) \
         ORDER BY key"
    );
    sqlx::query_as::<_, ServiceTemplateRow>(&q)
        .bind(org_id)
        .bind(identity_id)
        .fetch_all(pool)
        .await
}

pub async fn update(
    pool: &PgPool,
    id: Uuid,
    input: &UpdateServiceTemplate<'_>,
) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    let q = format!(
        "UPDATE service_templates SET \
         display_name = COALESCE($2, display_name), \
         description = COALESCE($3, description), \
         category = COALESCE($4, category), \
         hosts = COALESCE($5, hosts), \
         auth = COALESCE($6, auth), \
         actions = COALESCE($7, actions), \
         updated_at = now() \
         WHERE id = $1 \
         RETURNING {SELECT_COLS}"
    );
    sqlx::query_as::<_, ServiceTemplateRow>(&q)
        .bind(id)
        .bind(input.display_name)
        .bind(input.description)
        .bind(input.category)
        .bind(input.hosts)
        .bind(&input.auth)
        .bind(&input.actions)
        .fetch_optional(pool)
        .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM service_templates WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
