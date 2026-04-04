use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct IdentityRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub kind: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
    pub metadata: serde_json::Value,
    pub parent_id: Option<Uuid>,
    pub depth: i32,
    pub owner_id: Option<Uuid>,
    pub inherit_permissions: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

const COLUMNS: &str = "id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, created_at, updated_at";

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!(
        "INSERT INTO identities (org_id, name, kind, external_id) VALUES ($1, $2, $3, $4)
         RETURNING {COLUMNS}",
    ))
    .bind(org_id)
    .bind(name)
    .bind(kind)
    .bind(external_id)
    .fetch_one(pool)
    .await
}

pub async fn create_with_email(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    email: Option<&str>,
    metadata: serde_json::Value,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!(
        "INSERT INTO identities (org_id, name, kind, external_id, email, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING {COLUMNS}",
    ))
    .bind(org_id)
    .bind(name)
    .bind(kind)
    .bind(external_id)
    .bind(email)
    .bind(metadata)
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_with_parent(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    parent_id: Uuid,
    depth: i32,
    owner_id: Uuid,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!(
        "INSERT INTO identities (org_id, name, kind, external_id, parent_id, depth, owner_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING {COLUMNS}",
    ))
    .bind(org_id)
    .bind(name)
    .bind(kind)
    .bind(external_id)
    .bind(parent_id)
    .bind(depth)
    .bind(owner_id)
    .fetch_one(pool)
    .await
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!(
        "SELECT {COLUMNS} FROM identities WHERE email = $1 AND kind = 'user'",
    ))
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!("SELECT {COLUMNS} FROM identities WHERE id = $1",))
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!(
        "SELECT {COLUMNS} FROM identities WHERE org_id = $1 ORDER BY created_at",
    ))
    .bind(org_id)
    .fetch_all(pool)
    .await
}

pub async fn list_children(
    pool: &PgPool,
    parent_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!(
        "SELECT {COLUMNS} FROM identities WHERE parent_id = $1 ORDER BY created_at",
    ))
    .bind(parent_id)
    .fetch_all(pool)
    .await
}

pub async fn get_ancestor_chain(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(&format!(
        "WITH RECURSIVE chain AS (
            SELECT {COLUMNS} FROM identities WHERE id = $1
            UNION ALL
            SELECT i.id, i.org_id, i.name, i.kind, i.external_id, i.email, i.metadata,
                   i.parent_id, i.depth, i.owner_id, i.inherit_permissions,
                   i.created_at, i.updated_at
            FROM identities i
            INNER JOIN chain c ON i.id = c.parent_id
        )
        SELECT {COLUMNS} FROM chain ORDER BY depth ASC",
    ))
    .bind(identity_id)
    .fetch_all(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
