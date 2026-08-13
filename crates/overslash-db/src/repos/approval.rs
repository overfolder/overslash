use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApprovalRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub current_resolver_identity_id: Uuid,
    pub resolver_assigned_at: OffsetDateTime,
    pub action_summary: String,
    pub action_detail: Option<serde_json::Value>,
    pub disclosed_fields: Option<serde_json::Value>,
    /// Raw replay payload used by `POST /v1/approvals/{id}/call`. Carries
    /// either an HTTP `StoredCallRequest` (`{ action, filter, prefer_stream }`)
    /// or an MCP `StoredMcpCall` (`{ url, auth, tool, arguments }`),
    /// disambiguated at parse time by the top-level `tool` key. Distinct
    /// from `action_detail` (which may be the UI-facing redacted projection).
    /// NULL for platform-runtime approvals and pre-feature rows.
    pub replay_payload: Option<serde_json::Value>,
    pub permission_keys: Vec<String>,
    pub status: String,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolved_by: Option<String>,
    pub remember: bool,
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    /// System-derived metadata tags for the gated call (`sql:write`,
    /// `table:wh/orders`, `service:metabase`, …). Minted once at approval
    /// creation and copied onto the execution; see `overslash_core::tags`.
    pub tags: Vec<String>,
    /// `sync` | `async` — whether the original call asked to run off the
    /// request path (D62). A column rather than a field inside
    /// `replay_payload` because both triggers of a replay have to branch on it
    /// *before* parsing a payload that has three different shapes.
    pub execution_mode: String,
}

impl ApprovalRow {
    /// True when the gated call asked to run off the connection that triggers
    /// its replay — `async` or `hybrid` — so an approved replay is queued for
    /// the worker instead of dialled inline.
    ///
    /// `hybrid` collapses into `async` *here and nowhere else*. Its handoff
    /// race is a property of the original caller's connection; a replay is
    /// triggered either by a resolver's browser or by `spawn_auto_call`, which
    /// has no connection at all. Racing one trigger and queueing the other
    /// would make the same approval behave differently depending on which one
    /// fired — the failure the branch-in-one-helper shape was written to
    /// prevent. `execution_mode` still stores `'hybrid'`, so the approval card
    /// can report which mode was asked for.
    pub fn is_async(&self) -> bool {
        matches!(self.execution_mode.as_str(), "async" | "hybrid")
    }
}

/// One approval the expiry sweep just flipped.
///
/// Deliberately *not* an [`ApprovalRow`]: the sweep is cross-org and bulk, so
/// the batch it returns must stay small. This carries only what the emitter
/// needs — the audience pair (`identity_id`, `current_resolver_identity_id`),
/// the summary the event payload restates, and the tags the audit row is
/// filed under — and none of the jsonb columns (`action_detail`,
/// `disclosed_fields`, `replay_payload`), any one of which can be as large as
/// the request body that was gated.
#[derive(Debug, Clone)]
pub struct ExpiredApproval {
    pub id: Uuid,
    pub org_id: Uuid,
    /// The requester — the identity whose action was gated.
    pub identity_id: Uuid,
    /// Whoever was holding the decision when it ran out of time.
    pub current_resolver_identity_id: Uuid,
    pub action_summary: String,
    pub tags: Vec<String>,
}

/// Everything an approval is born with. `org_id` is deliberately absent: it
/// comes from the caller's `OrgScope`, so a construction site cannot smuggle a
/// foreign tenant's id into the insert.
pub struct CreateApproval<'a> {
    pub identity_id: Uuid,
    pub current_resolver_identity_id: Uuid,
    pub action_summary: &'a str,
    pub action_detail: Option<serde_json::Value>,
    pub disclosed_fields: Option<serde_json::Value>,
    pub replay_payload: Option<serde_json::Value>,
    pub permission_keys: &'a [String],
    pub token: &'a str,
    pub expires_at: OffsetDateTime,
    pub tags: &'a [String],
    /// `"sync"` | `"async"`, from the request's `execution` mode.
    pub execution_mode: &'a str,
}

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    input: &CreateApproval<'_>,
) -> Result<ApprovalRow, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "INSERT INTO approvals (org_id, identity_id, current_resolver_identity_id, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, token, expires_at, tags, execution_mode)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode",
        org_id,
        input.identity_id,
        input.current_resolver_identity_id,
        input.action_summary,
        input.action_detail.clone() as Option<serde_json::Value>,
        input.disclosed_fields.clone() as Option<serde_json::Value>,
        input.replay_payload.clone() as Option<serde_json::Value>,
        input.permission_keys,
        input.token,
        input.expires_at,
        input.tags,
        input.execution_mode,
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
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode
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
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode
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
         RETURNING id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode",
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
          RETURNING id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode",
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
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode
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
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode
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
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode
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
        "SELECT id, org_id, identity_id, current_resolver_identity_id, resolver_assigned_at, action_summary, action_detail, disclosed_fields, replay_payload, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, tags, execution_mode
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
               a.token as "token!", a.expires_at as "expires_at!", a.created_at as "created_at!", a.tags as "tags!", a.execution_mode as "execution_mode!"
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

/// List pending approvals whose **requester** is `root_id` itself or any
/// descendant of it. Used by the cascade resolver after a remembered rule is
/// committed at `root_id` — those approvals are the only ones the new rule
/// could possibly satisfy.
///
/// Caller is responsible for excluding the just-resolved approval id from
/// the returned set.
pub(crate) async fn list_pending_for_descendants(
    pool: &PgPool,
    org_id: Uuid,
    root_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        r#"WITH RECURSIVE descendants AS (
            SELECT id FROM identities WHERE id = $2 AND org_id = $1
            UNION ALL
            SELECT i.id FROM identities i
            INNER JOIN descendants d ON i.parent_id = d.id
            WHERE i.org_id = $1
        )
        SELECT a.id as "id!", a.org_id as "org_id!", a.identity_id as "identity_id!",
               a.current_resolver_identity_id as "current_resolver_identity_id!",
               a.resolver_assigned_at as "resolver_assigned_at!",
               a.action_summary as "action_summary!", a.action_detail,
               a.disclosed_fields,
               a.replay_payload,
               a.permission_keys as "permission_keys!", a.status as "status!",
               a.resolved_at, a.resolved_by, a.remember as "remember!",
               a.token as "token!", a.expires_at as "expires_at!", a.created_at as "created_at!", a.tags as "tags!", a.execution_mode as "execution_mode!"
        FROM approvals a
        WHERE a.org_id = $1
          AND a.status = 'pending'
          AND a.identity_id IN (SELECT id FROM descendants)
        ORDER BY a.created_at ASC"#,
        org_id,
        root_id,
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
        "SELECT a.id, a.org_id, a.identity_id, a.current_resolver_identity_id, a.resolver_assigned_at, a.action_summary, a.action_detail, a.disclosed_fields, a.replay_payload, a.permission_keys, a.status, a.resolved_at, a.resolved_by, a.remember, a.token, a.expires_at, a.created_at, a.tags, a.execution_mode
         FROM approvals a
         JOIN orgs o ON o.id = a.org_id
         WHERE a.status = 'pending'
           AND o.approval_auto_bubble_secs > 0
           AND a.resolver_assigned_at < now() - make_interval(secs => o.approval_auto_bubble_secs)",
    )
    .fetch_all(pool)
    .await
}

/// Cross-org maintenance: expire at most `limit` pending approvals whose
/// `expires_at` has passed, returning what was flipped. Exposed via
/// `SystemScope` only.
///
/// `limit` is what keeps the sweep bounded in *rows*; [`ExpiredApproval`] is
/// what keeps it bounded in *bytes*. `ORDER BY expires_at` drives the selection
/// through `idx_approvals_expires`, the partial index this predicate was
/// written for, and drains the oldest backlog first. `FOR UPDATE SKIP LOCKED`
/// lets two replicas' ticks overlap without either blocking on the other or
/// expiring the same approval twice.
///
/// The `MATERIALIZED` CTE is load-bearing, not style. Written the obvious way —
/// `WHERE id IN (SELECT ... LIMIT $1 FOR UPDATE SKIP LOCKED)` — the limit is
/// only as good as the plan: given any additional qual on the outer table the
/// planner is free to choose a nested-loop semi-join with the subquery on the
/// inner side, rescanning (and re-locking, and re-`LIMIT`ing) it once per outer
/// row. That silently updates and returns *more* rows than `limit`, which here
/// means emitting more events than the tick is bounded to. A `MATERIALIZED` CTE
/// is an explicit optimization fence: it is evaluated exactly once, so the bound
/// is a property of the statement rather than of the planner's mood.
pub(crate) async fn expire_stale(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<ExpiredApproval>, sqlx::Error> {
    sqlx::query_as!(
        ExpiredApproval,
        "WITH stale AS MATERIALIZED (
             SELECT id FROM approvals
             WHERE status = 'pending' AND expires_at < now()
             ORDER BY expires_at
             LIMIT $1
             FOR UPDATE SKIP LOCKED
         )
         UPDATE approvals
            SET status = 'expired', resolved_at = now(), resolved_by = 'system'
           FROM stale
          WHERE approvals.id = stale.id
      RETURNING approvals.id, approvals.org_id, approvals.identity_id,
                approvals.current_resolver_identity_id, approvals.action_summary,
                approvals.tags",
        limit,
    )
    .fetch_all(pool)
    .await
}
