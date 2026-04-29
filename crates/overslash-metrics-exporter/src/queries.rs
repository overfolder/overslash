//! Business-metric SQL.
//!
//! Each function is a single read-only query and returns a small POD struct.
//! `collect_all` runs every query in parallel via `tokio::try_join!` and
//! gathers the results into [`BusinessMetrics`]. Keep individual queries
//! cheap (`COUNT(*)`, `GROUP BY` of low-cardinality columns) so the whole
//! sweep finishes well inside the Cloud Scheduler 5-minute window.
//!
//! Cardinality discipline: never `GROUP BY` an unbounded column (org_id,
//! identity_id, secret name). `template_key` is bounded to the top 20 to
//! cap series count even as more services are added.

use anyhow::Result;
use sqlx::PgPool;

/// All business metrics gathered in one sweep. Each field is a vector of
/// `(label_value, count)` rows, or a single scalar when there is no
/// natural grouping. Empty vectors are valid (e.g., a fresh deployment).
#[derive(Debug, Default)]
pub struct BusinessMetrics {
    /// Per-tier org count. Tier ∈ {`personal`, `team_active`, `team_other`}.
    pub orgs_by_tier: Vec<(String, i64)>,
    pub users_total: i64,
    /// Per-kind identity count. Kind ∈ {`user`, `agent`, `sub_agent`}.
    pub identities_by_kind: Vec<(String, i64)>,
    /// Per-kind identities that have been active in the last 7 days
    /// (`last_active_at > now() - 7d`). Excludes archived rows.
    pub identities_active_7d_by_kind: Vec<(String, i64)>,
    pub api_keys_active: i64,
    pub secrets_total: i64,
    pub secret_versions_total: i64,
    /// Per-provider active OAuth connections.
    pub connections_by_provider: Vec<(String, i64)>,
    /// Top-20 service templates by active instance count. Top-20 cap keeps
    /// the time-series count bounded even as the catalog grows.
    pub instances_by_template: Vec<(String, i64)>,
    pub approvals_pending: i64,
    /// Age in seconds of the oldest pending approval. 0 when none pending.
    pub approvals_pending_oldest_seconds: f64,
    /// Per-decision count of approvals resolved in the last 24h.
    /// Decision ∈ {`allowed`, `denied`, `expired`}.
    pub approvals_resolved_24h_by_decision: Vec<(String, i64)>,
    /// Per-status count of executions created in the last 24h.
    pub executions_24h_by_status: Vec<(String, i64)>,
    /// Top-10 audit-log actions in the last 24h.
    pub audit_events_24h_by_action: Vec<(String, i64)>,
    /// Webhook deliveries that exhausted retries in the last 24h, by event.
    pub webhook_failures_24h_by_event: Vec<(String, i64)>,
}

pub async fn collect_all(db: &PgPool) -> Result<BusinessMetrics> {
    let (
        orgs_by_tier,
        users_total,
        identities_by_kind,
        identities_active_7d_by_kind,
        api_keys_active,
        secrets_total,
        secret_versions_total,
        connections_by_provider,
        instances_by_template,
        approvals_pending,
        approvals_pending_oldest_seconds,
        approvals_resolved_24h_by_decision,
        executions_24h_by_status,
        audit_events_24h_by_action,
        webhook_failures_24h_by_event,
    ) = tokio::try_join!(
        orgs_by_tier(db),
        users_total(db),
        identities_by_kind(db),
        identities_active_7d_by_kind(db),
        api_keys_active(db),
        secrets_total(db),
        secret_versions_total(db),
        connections_by_provider(db),
        instances_by_template(db),
        approvals_pending(db),
        approvals_pending_oldest_seconds(db),
        approvals_resolved_24h_by_decision(db),
        executions_24h_by_status(db),
        audit_events_24h_by_action(db),
        webhook_failures_24h_by_event(db),
    )?;

    Ok(BusinessMetrics {
        orgs_by_tier,
        users_total,
        identities_by_kind,
        identities_active_7d_by_kind,
        api_keys_active,
        secrets_total,
        secret_versions_total,
        connections_by_provider,
        instances_by_template,
        approvals_pending,
        approvals_pending_oldest_seconds,
        approvals_resolved_24h_by_decision,
        executions_24h_by_status,
        audit_events_24h_by_action,
        webhook_failures_24h_by_event,
    })
}

async fn orgs_by_tier(db: &PgPool) -> Result<Vec<(String, i64)>> {
    // Three buckets cover every org without leaking org_id:
    // - `personal`: orgs.is_personal = true (one per user).
    // - `team_active`: a Team org with an active billing subscription.
    // - `team_other`: every other Team org (free trial, lapsed, self-hosted).
    let rows = sqlx::query!(
        r#"
        SELECT
            CASE
                WHEN o.is_personal THEN 'personal'
                WHEN s.status = 'active' THEN 'team_active'
                ELSE 'team_other'
            END AS "tier!",
            COUNT(*)::bigint AS "count!"
        FROM orgs o
        LEFT JOIN org_subscriptions s ON s.org_id = o.id
        GROUP BY 1
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.tier, r.count)).collect())
}

async fn users_total(db: &PgPool) -> Result<i64> {
    Ok(
        sqlx::query_scalar!(r#"SELECT COUNT(*)::bigint AS "c!" FROM users"#)
            .fetch_one(db)
            .await?,
    )
}

async fn identities_by_kind(db: &PgPool) -> Result<Vec<(String, i64)>> {
    // Exclude archived rows: they describe identities that no longer exist
    // from the user's perspective and would inflate the count for weeks
    // before the purge sweep removes them.
    let rows = sqlx::query!(
        r#"
        SELECT kind AS "kind!", COUNT(*)::bigint AS "count!"
        FROM identities
        WHERE archived_at IS NULL
        GROUP BY kind
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.kind, r.count)).collect())
}

async fn identities_active_7d_by_kind(db: &PgPool) -> Result<Vec<(String, i64)>> {
    let rows = sqlx::query!(
        r#"
        SELECT kind AS "kind!", COUNT(*)::bigint AS "count!"
        FROM identities
        WHERE archived_at IS NULL
          AND last_active_at > now() - INTERVAL '7 days'
        GROUP BY kind
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.kind, r.count)).collect())
}

async fn api_keys_active(db: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar!(
        r#"SELECT COUNT(*)::bigint AS "c!" FROM api_keys WHERE revoked_at IS NULL"#,
    )
    .fetch_one(db)
    .await?)
}

async fn secrets_total(db: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar!(
        r#"SELECT COUNT(*)::bigint AS "c!" FROM secrets WHERE deleted_at IS NULL"#,
    )
    .fetch_one(db)
    .await?)
}

async fn secret_versions_total(db: &PgPool) -> Result<i64> {
    Ok(
        sqlx::query_scalar!(r#"SELECT COUNT(*)::bigint AS "c!" FROM secret_versions"#)
            .fetch_one(db)
            .await?,
    )
}

async fn connections_by_provider(db: &PgPool) -> Result<Vec<(String, i64)>> {
    // `connections.provider_key` is the OAuth provider id from the registry
    // (e.g. `google`, `github`). Bounded by the registry, safe as a label.
    let rows = sqlx::query!(
        r#"
        SELECT provider_key AS "provider!", COUNT(*)::bigint AS "count!"
        FROM connections
        GROUP BY provider_key
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.provider, r.count)).collect())
}

async fn instances_by_template(db: &PgPool) -> Result<Vec<(String, i64)>> {
    // Top-20 only: keeps the per-template series count bounded even when
    // an org loads dozens of niche templates. The long-tail can still be
    // reconstructed from the API's `overslash_action_executions_total`.
    let rows = sqlx::query!(
        r#"
        SELECT template_key AS "template!", COUNT(*)::bigint AS "count!"
        FROM service_instances
        WHERE status = 'active'
        GROUP BY template_key
        ORDER BY COUNT(*) DESC
        LIMIT 20
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.template, r.count)).collect())
}

async fn approvals_pending(db: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar!(
        r#"SELECT COUNT(*)::bigint AS "c!" FROM approvals WHERE status = 'pending'"#,
    )
    .fetch_one(db)
    .await?)
}

async fn approvals_pending_oldest_seconds(db: &PgPool) -> Result<f64> {
    // COALESCE → 0 when nothing is pending so the metric never disappears.
    let secs: Option<f64> = sqlx::query_scalar!(
        r#"
        SELECT EXTRACT(EPOCH FROM (now() - MIN(created_at)))::float8
        FROM approvals
        WHERE status = 'pending'
        "#,
    )
    .fetch_one(db)
    .await?;
    Ok(secs.unwrap_or(0.0))
}

async fn approvals_resolved_24h_by_decision(db: &PgPool) -> Result<Vec<(String, i64)>> {
    let rows = sqlx::query!(
        r#"
        SELECT status AS "status!", COUNT(*)::bigint AS "count!"
        FROM approvals
        WHERE status IN ('allowed', 'denied', 'expired')
          AND COALESCE(resolved_at, expires_at) > now() - INTERVAL '24 hours'
        GROUP BY status
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.status, r.count)).collect())
}

async fn executions_24h_by_status(db: &PgPool) -> Result<Vec<(String, i64)>> {
    let rows = sqlx::query!(
        r#"
        SELECT status AS "status!", COUNT(*)::bigint AS "count!"
        FROM executions
        WHERE created_at > now() - INTERVAL '24 hours'
        GROUP BY status
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.status, r.count)).collect())
}

async fn audit_events_24h_by_action(db: &PgPool) -> Result<Vec<(String, i64)>> {
    // Top-10 only — long-tail audit actions would explode the label space.
    // `action` strings come from the call sites (closed enum in practice),
    // but we still cap to defend against future drift.
    let rows = sqlx::query!(
        r#"
        SELECT action AS "action!", COUNT(*)::bigint AS "count!"
        FROM audit_log
        WHERE created_at > now() - INTERVAL '24 hours'
        GROUP BY action
        ORDER BY COUNT(*) DESC
        LIMIT 10
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.action, r.count)).collect())
}

async fn webhook_failures_24h_by_event(db: &PgPool) -> Result<Vec<(String, i64)>> {
    // Mirrors the `attempts < 5` retry filter in the dispatcher: a delivery
    // is "exhausted" once attempts hit 5 and it has never been delivered.
    let rows = sqlx::query!(
        r#"
        SELECT event AS "event!", COUNT(*)::bigint AS "count!"
        FROM webhook_deliveries
        WHERE delivered_at IS NULL
          AND attempts >= 5
          AND created_at > now() - INTERVAL '24 hours'
        GROUP BY event
        "#,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.event, r.count)).collect())
}
