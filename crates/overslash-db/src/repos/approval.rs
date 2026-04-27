use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ApprovalRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub current_resolver_identity_id: Uuid,
    pub resolver_assigned_at: OffsetDateTime,
    pub action_summary: String,
    pub action_detail: Option<serde_json::Value>,
    pub disclosed_fields: Option<serde_json::Value>,
    /// Raw replay payload (full ActionRequest + filter + prefer_stream).
    /// Distinct from `action_detail` (which may be the UI-facing redacted
    /// projection). NULL for MCP-runtime approvals and pre-feature rows.
    pub replay_payload: Option<serde_json::Value>,
    pub permission_keys: Vec<String>,
    pub status: String,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolved_by: Option<String>,
    pub remember: bool,
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

pub struct CreateApproval<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub current_resolver_identity_id: Uuid,
    pub action_summary: &'a str,
    pub action_detail: Option<serde_json::Value>,
    pub disclosed_fields: Option<serde_json::Value>,
    pub replay_payload: Option<serde_json::Value>,
    pub permission_keys: &'a [String],
    pub token: &'a str,
    pub expires_at: OffsetDateTime,
}

pub(crate) async fn create(
    pool: &PgPool,
    input: &CreateApproval<'_>,
) -> Result<ApprovalRow, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "INSERT INTO approvals (org_id, identity_id, current_resolver_identity_id, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, token, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at",
        input.org_id,
        input.identity_id,
        input.current_resolver_identity_id,
        input.action_summary,
        input.action_detail.clone() as Option<serde_json::Value>,
        input.disclosed_fields.clone() as Option<serde_json::Value>,
        input.replay_payload.clone() as Option<serde_json::Value>,
        input.permission_keys,
        input.token,
        input.expires_at,
    )
    .fetch_one(pool)
    .await
}

/// Double-key lookup: id AND org_id. Cross-tenant id probes return None
/// rather than leaking the row's existence.
pub(crate) async fn get_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Double-key lookup: token AND org_id. A token guessed/leaked from another
/// org cannot be used to read across tenants.
pub(crate) async fn get_by_token(
    pool: &PgPool,
    org_id: Uuid,
    token: &str,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals WHERE token = $1 AND org_id = $2",
        token,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically resolve a pending approval, with optimistic locking on the
/// current resolver and double-key org filter. Returns None if the approval
/// is not pending, the resolver has been advanced, OR the approval belongs
/// to a different org.
pub(crate) async fn resolve(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    status: &str,
    resolved_by: &str,
    remember: bool,
    expected_resolver: Uuid,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "UPDATE approvals SET status = $2, resolved_at = now(), resolved_by = $3, remember = $4
         WHERE id = $1 AND org_id = $6 AND status = 'pending' AND current_resolver_identity_id = $5
         RETURNING id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at",
        id,
        status,
        resolved_by,
        remember,
        expected_resolver,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically advance the current resolver of a pending approval (bubble up),
/// with optimistic locking on `expected_resolver` and double-key org filter.
/// Returns None if the approval is not pending, has been concurrently bubbled,
/// OR belongs to a different org.
pub(crate) async fn update_resolver(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    new_resolver: Uuid,
    expected_resolver: Uuid,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "UPDATE approvals
            SET current_resolver_identity_id = $2,
                resolver_assigned_at = now()
          WHERE id = $1 AND org_id = $4 AND status = 'pending' AND current_resolver_identity_id = $3
          RETURNING id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at",
        id,
        new_resolver,
        expected_resolver,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_pending_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals WHERE org_id = $1 AND status = 'pending' ORDER BY created_at DESC",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// List pending approvals requested by `identity_id` (`?scope=mine`).
pub(crate) async fn list_mine(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals
         WHERE org_id = $1 AND identity_id = $2 AND status = 'pending'
         ORDER BY created_at DESC",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List approvals for `identity_id` filtered by an arbitrary `status` string.
/// Used when the caller explicitly passes `?status=<value>` (e.g. `allowed`).
pub(crate) async fn list_mine_by_status(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    status: &str,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals
         WHERE org_id = $1 AND identity_id = $2 AND status = $3
         ORDER BY created_at DESC",
        org_id,
        identity_id,
        status,
    )
    .fetch_all(pool)
    .await
}

/// List pending approvals where the caller is the current resolver right now
/// (`?scope=assigned`). Strict "inbox" view — does NOT include approvals
/// sitting on a descendant of the caller. Excludes self-requested approvals.
pub(crate) async fn list_assigned_to_identity(
    pool: &PgPool,
    org_id: Uuid,
    caller_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals
         WHERE org_id = $1
           AND status = 'pending'
           AND current_resolver_identity_id = $2
           AND identity_id <> $2
         ORDER BY created_at DESC",
        org_id,
        caller_id,
    )
    .fetch_all(pool)
    .await
}

/// List pending approvals the caller can act on (`?scope=actionable`).
///
/// An approval is actionable for `caller_id` when:
///   * `caller_id` is the current resolver, or any descendant of the caller is
///     the current resolver (an ancestor can always step in for a descendant), AND
///   * `caller_id` is NOT the requester (an identity may never resolve its own
///     approval — SPEC §5).
pub(crate) async fn list_actionable_for_identity(
    pool: &PgPool,
    org_id: Uuid,
    caller_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        r#"WITH RECURSIVE descendants AS (
            SELECT id FROM identities WHERE id = $2
            UNION ALL
            SELECT i.id FROM identities i
            INNER JOIN descendants d ON i.parent_id = d.id
        )
        SELECT a.id as "id!", a.org_id as "org_id!", a.identity_id as "identity_id!",
               a.current_resolver_identity_id as "current_resolver_identity_id!",
               a.resolver_assigned_at as "resolver_assigned_at!",
               a.action_summary as "action_summary!", a.action_detail,
               a.disclosed_fields,
               a.replay_payload,
               a.permission_keys as "permission_keys!", a.status as "status!",
               a.resolved_at, a.resolved_by, a.remember as "remember!",
               a.token as "token!", a.expires_at as "expires_at!", a.created_at as "created_at!"
        FROM approvals a
        WHERE a.org_id = $1
          AND a.status = 'pending'
          AND a.identity_id <> $2
          AND a.current_resolver_identity_id IN (SELECT id FROM descendants)
        ORDER BY a.created_at DESC"#,
        org_id,
        caller_id,
    )
    .fetch_all(pool)
    .await
}

/// List pending approvals whose current resolver has held them longer than
/// their org's `approval_auto_bubble_secs` setting (and the setting is non-zero).
/// Cross-org by design — exposed via `SystemScope` only.
pub(crate) async fn list_pending_for_auto_bubble(
    pool: &PgPool,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT a.id, a.org_id, a.identity_id, a.current_resolver_identity_id, a.resolver_assigned_at, a.action_summary, a.action_detail, a.disclosed_fields, a.replay_payload, a.permission_keys, a.status, a.resolved_at, a.resolved_by, a.remember, a.token, a.expires_at, a.created_at
         FROM approvals a
         JOIN orgs o ON o.id = a.org_id
         WHERE a.status = 'pending'
           AND o.approval_auto_bubble_secs > 0
           AND a.resolver_assigned_at < now() - make_interval(secs => o.approval_auto_bubble_secs)",
    )
    .fetch_all(pool)
    .await
}

/// Cross-org maintenance: expire any pending approval whose `expires_at`
/// has passed. Exposed via `SystemScope` only.
pub(crate) async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE approvals SET status = 'expired', resolved_at = now(), resolved_by = 'system'
         WHERE status = 'pending' AND expires_at < now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
