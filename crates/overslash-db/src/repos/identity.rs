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
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

const SELECT_COLS: &str = "id, org_id, name, kind, external_id, email, metadata, parent_id, depth, created_at, updated_at";

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    parent_id: Option<Uuid>,
) -> Result<IdentityRow, sqlx::Error> {
    let depth = match parent_id {
        Some(pid) => {
            let parent = sqlx::query_scalar::<_, i32>(
                "SELECT depth FROM identities WHERE id = $1",
            )
            .bind(pid)
            .fetch_one(pool)
            .await?;
            parent + 1
        }
        None => 0,
    };

    let query = format!(
        "INSERT INTO identities (org_id, name, kind, external_id, parent_id, depth) VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING {SELECT_COLS}"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(org_id)
        .bind(name)
        .bind(kind)
        .bind(external_id)
        .bind(parent_id)
        .bind(depth)
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
    let query = format!(
        "INSERT INTO identities (org_id, name, kind, external_id, email, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING {SELECT_COLS}"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(org_id)
        .bind(name)
        .bind(kind)
        .bind(external_id)
        .bind(email)
        .bind(metadata)
        .fetch_one(pool)
        .await
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<IdentityRow>, sqlx::Error> {
    let query = format!(
        "SELECT {SELECT_COLS} FROM identities WHERE email = $1 AND kind = 'user'"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(email)
        .fetch_optional(pool)
        .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
    let query = format!(
        "SELECT {SELECT_COLS} FROM identities WHERE id = $1"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<IdentityRow>, sqlx::Error> {
    let query = format!(
        "SELECT {SELECT_COLS} FROM identities WHERE org_id = $1 ORDER BY depth, created_at"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(org_id)
        .fetch_all(pool)
        .await
}

pub async fn update(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    name: &str,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    let query = format!(
        "UPDATE identities SET name = $1, updated_at = now() WHERE id = $2 AND org_id = $3
         RETURNING {SELECT_COLS}"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(name)
        .bind(id)
        .bind(org_id)
        .fetch_optional(pool)
        .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
