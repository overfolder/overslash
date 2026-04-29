# Monitoring, alerts, dashboards, uptime checks for Overslash.
#
# - Service metrics (Prometheus) are scraped from the API's
#   `/internal/metrics` endpoint by an OTel sidecar (configured in the
#   cloud-run module) and ingested into Google Managed Prometheus. Their
#   resource type in Cloud Monitoring is `prometheus_target`.
# - Business metrics are pushed by the metrics-exporter Cloud Run Job to
#   `custom.googleapis.com/overslash/business/*`, resource type
#   `generic_task` with `namespace=overslash`, `job=metrics-exporter`.
# - Cloud Run / Cloud SQL platform metrics use their native resource types.

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  # Filters as they reach the Cloud Monitoring API verbatim — raw quotes,
  # consumed directly by alert policy `filter` fields.
  api_filter      = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"${var.api_service_name}\""
  db_filter       = "resource.type = \"cloudsql_database\" AND resource.labels.database_id = \"${var.project_id}:${var.cloud_sql_instance_name}\""
  business_filter = "resource.type = \"generic_task\" AND resource.labels.namespace = \"overslash\" AND resource.labels.job = \"metrics-exporter\""

  # P0 channels: PagerDuty (if configured) + email fallback.
  p0_channels = concat(
    var.pagerduty_integration_key != "" ? [google_monitoring_notification_channel.pagerduty[0].id] : [],
    [google_monitoring_notification_channel.email.id],
  )

  # P1/P2 channels: email only — user has no Slack.
  p1_channels = [google_monitoring_notification_channel.email.id]
  p2_channels = [google_monitoring_notification_channel.email.id]
}
