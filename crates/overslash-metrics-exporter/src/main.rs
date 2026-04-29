//! Overslash business-metrics exporter — Cloud Run Job.
//!
//! Wakes on a Cloud Scheduler tick, queries Postgres in parallel, and pushes
//! the result to Google Cloud Monitoring as `custom.googleapis.com/overslash/business/*`
//! gauges. Exits 0 on success, non-zero on failure (Cloud Run Job records
//! the failure for retry / alerting).
//!
//! Dry-run mode (`EXPORTER_DRY_RUN=1`) prints the payload as JSON and skips
//! the HTTPS POST — used for local validation and the unit tests.

mod cloud_monitoring;
mod queries;

use std::env;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use tracing::info;

use crate::cloud_monitoring::{
    MonitoredResource, TimeSeries, business_resource, make_gauge, make_gauge_int, write_time_series,
};
use crate::queries::BusinessMetrics;

const METRIC_PREFIX: &str = "custom.googleapis.com/overslash/business";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_tracing();

    let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let dry_run = env::var("EXPORTER_DRY_RUN")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE"));
    let project_id = env::var("GCP_PROJECT_ID").ok();
    let location = env::var("GCP_REGION").unwrap_or_else(|_| "us-central1".into());

    if !dry_run && project_id.is_none() {
        anyhow::bail!("GCP_PROJECT_ID is required unless EXPORTER_DRY_RUN=1");
    }

    let db = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(&database_url)
        .await
        .context("failed to connect to Postgres")?;

    info!("Collecting business metrics");
    let metrics = queries::collect_all(&db).await?;
    log_collected(&metrics);

    let now = chrono::Utc::now().to_rfc3339();
    let resource = business_resource(project_id.as_deref().unwrap_or("dry-run"), &location);
    let series = build_time_series(&metrics, &now, &resource);
    info!(count = series.len(), "Built time series");

    if dry_run {
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "timeSeries": series,
        }))?;
        println!("{body}");
        return Ok(());
    }

    let project_id = project_id.expect("checked above");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build reqwest client")?;
    write_time_series(&project_id, series, &client).await?;
    info!("Metrics exported");
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("overslash_metrics_exporter=info,info"));
    let json = env::var("LOG_FORMAT")
        .ok()
        .is_some_and(|v| v.eq_ignore_ascii_case("json"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn log_collected(m: &BusinessMetrics) {
    info!(
        users_total = m.users_total,
        api_keys_active = m.api_keys_active,
        secrets_total = m.secrets_total,
        secret_versions_total = m.secret_versions_total,
        approvals_pending = m.approvals_pending,
        approvals_pending_oldest_seconds = m.approvals_pending_oldest_seconds,
        identity_kinds = m.identities_by_kind.len(),
        provider_count = m.connections_by_provider.len(),
        template_count = m.instances_by_template.len(),
        "Metrics collected",
    );
}

/// Build the full set of time-series payloads from one [`BusinessMetrics`]
/// snapshot. Pure function over the domain types — exercised by tests
/// without a live DB or GCP credentials.
fn build_time_series(
    m: &BusinessMetrics,
    now: &str,
    resource: &MonitoredResource,
) -> Vec<TimeSeries> {
    let mut out = Vec::new();

    for (tier, count) in &m.orgs_by_tier {
        out.push(make_gauge_int(
            &metric("orgs_total"),
            &[("tier", tier)],
            *count,
            now,
            resource,
        ));
    }
    out.push(make_gauge_int(
        &metric("users_total"),
        &[],
        m.users_total,
        now,
        resource,
    ));
    for (kind, count) in &m.identities_by_kind {
        out.push(make_gauge_int(
            &metric("identities_total"),
            &[("kind", kind)],
            *count,
            now,
            resource,
        ));
    }
    for (kind, count) in &m.identities_active_7d_by_kind {
        out.push(make_gauge_int(
            &metric("identities_active_7d"),
            &[("kind", kind)],
            *count,
            now,
            resource,
        ));
    }
    out.push(make_gauge_int(
        &metric("api_keys_active"),
        &[],
        m.api_keys_active,
        now,
        resource,
    ));
    out.push(make_gauge_int(
        &metric("secrets_total"),
        &[],
        m.secrets_total,
        now,
        resource,
    ));
    out.push(make_gauge_int(
        &metric("secret_versions_total"),
        &[],
        m.secret_versions_total,
        now,
        resource,
    ));
    for (provider, count) in &m.connections_by_provider {
        out.push(make_gauge_int(
            &metric("connections_active"),
            &[("provider", provider)],
            *count,
            now,
            resource,
        ));
    }
    for (template, count) in &m.instances_by_template {
        out.push(make_gauge_int(
            &metric("service_instances_total"),
            &[("template_key", template)],
            *count,
            now,
            resource,
        ));
    }
    out.push(make_gauge_int(
        &metric("approvals_pending"),
        &[],
        m.approvals_pending,
        now,
        resource,
    ));
    out.push(make_gauge(
        &metric("approvals_pending_oldest_seconds"),
        &[],
        m.approvals_pending_oldest_seconds,
        now,
        resource,
    ));
    for (decision, count) in &m.approvals_resolved_24h_by_decision {
        out.push(make_gauge_int(
            &metric("approvals_resolved_24h"),
            &[("decision", decision)],
            *count,
            now,
            resource,
        ));
    }
    for (status, count) in &m.executions_24h_by_status {
        out.push(make_gauge_int(
            &metric("executions_24h"),
            &[("status", status)],
            *count,
            now,
            resource,
        ));
    }
    for (action, count) in &m.audit_events_24h_by_action {
        out.push(make_gauge_int(
            &metric("audit_events_24h"),
            &[("action", action)],
            *count,
            now,
            resource,
        ));
    }
    for (event, count) in &m.webhook_failures_24h_by_event {
        out.push(make_gauge_int(
            &metric("webhook_failures_24h"),
            &[("event_type", event)],
            *count,
            now,
            resource,
        ));
    }

    out
}

fn metric(name: &str) -> String {
    format!("{METRIC_PREFIX}/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_metrics() -> BusinessMetrics {
        BusinessMetrics {
            orgs_by_tier: vec![("personal".into(), 7), ("team_active".into(), 1)],
            users_total: 42,
            identities_by_kind: vec![
                ("user".into(), 7),
                ("agent".into(), 11),
                ("sub_agent".into(), 3),
            ],
            identities_active_7d_by_kind: vec![("user".into(), 5)],
            api_keys_active: 19,
            secrets_total: 5,
            secret_versions_total: 8,
            connections_by_provider: vec![("google".into(), 4), ("github".into(), 2)],
            instances_by_template: vec![("gmail".into(), 3), ("github".into(), 2)],
            approvals_pending: 4,
            approvals_pending_oldest_seconds: 312.5,
            approvals_resolved_24h_by_decision: vec![("allowed".into(), 10), ("denied".into(), 1)],
            executions_24h_by_status: vec![("executed".into(), 10), ("failed".into(), 2)],
            audit_events_24h_by_action: vec![("approval.resolved".into(), 11)],
            webhook_failures_24h_by_event: vec![],
        }
    }

    #[test]
    fn metric_prefix_is_applied() {
        assert_eq!(
            metric("foo"),
            "custom.googleapis.com/overslash/business/foo"
        );
    }

    #[test]
    fn build_time_series_emits_one_row_per_label_value() {
        let r = business_resource("p", "us-central1");
        let m = fake_metrics();
        let series = build_time_series(&m, "2026-04-29T00:00:00Z", &r);

        // 2 orgs_by_tier + 1 users_total + 3 identities_by_kind + 1 active_7d
        // + 1 api_keys + 1 secrets + 1 secret_versions
        // + 2 connections + 2 instances
        // + 1 approvals_pending + 1 oldest_seconds
        // + 2 approvals_resolved + 2 executions + 1 audit + 0 webhook = 21
        assert_eq!(series.len(), 21);
        assert!(series.iter().all(|s| {
            s.metric
                .metric_type
                .starts_with("custom.googleapis.com/overslash/business/")
        }));
        assert!(series.iter().any(|s| {
            s.metric
                .metric_type
                .ends_with("approvals_pending_oldest_seconds")
                && s.points[0].value.double_value == Some(312.5)
        }));
    }

    #[test]
    fn build_time_series_handles_empty_metrics() {
        let r = business_resource("p", "us-central1");
        let m = BusinessMetrics::default();
        let series = build_time_series(&m, "2026-04-29T00:00:00Z", &r);
        // The unconditional scalars still emit a series each:
        // users_total, api_keys_active, secrets_total, secret_versions_total,
        // approvals_pending, approvals_pending_oldest_seconds = 6
        assert_eq!(series.len(), 6);
    }

    #[test]
    fn build_time_series_label_values_are_attached() {
        let r = business_resource("p", "us-central1");
        let m = fake_metrics();
        let series = build_time_series(&m, "2026-04-29T00:00:00Z", &r);
        let identities = series
            .iter()
            .filter(|s| s.metric.metric_type.ends_with("identities_total"))
            .collect::<Vec<_>>();
        assert_eq!(identities.len(), 3);
        let kinds: Vec<&str> = identities
            .iter()
            .filter_map(|s| s.metric.labels.get("kind").map(String::as_str))
            .collect();
        assert!(kinds.contains(&"user"));
        assert!(kinds.contains(&"agent"));
        assert!(kinds.contains(&"sub_agent"));
    }
}
