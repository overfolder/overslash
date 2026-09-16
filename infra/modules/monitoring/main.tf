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
  # Dashboards are always created so operators can eyeball metrics on
  # environments where we don't want pages (e.g. dev). Alerts and the
  # backing notification channels live behind this flag.
  alerts_enabled = var.alert_email != ""

  api_filter      = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"${var.api_service_name}\""
  db_filter       = "resource.type = \"cloudsql_database\" AND resource.labels.database_id = \"${var.project_id}:${var.cloud_sql_instance_name}\""
  business_filter = "resource.type = \"generic_task\" AND resource.labels.namespace = \"overslash\" AND resource.labels.job = \"metrics-exporter\""

  # Label matchers excluding every path whose duration is a reading of our own
  # configuration rather than of the gateway's health. Used by the
  # `[P1] API Slow Requests` alert, whose numerator, denominator and rate guard
  # must all carry the identical set or the ratio is nonsense — which is why
  # this is one shared string and not three copies.
  #
  #   /v1/events/stream        SSE; lives EVENTS_STREAM_MAX_CONNECTION_SECS (30s)
  #                            by design and then closes (SPEC.md S10)
  #   /v1/actions/call         synchronous upstream proxy, bounded by the D56
  #                            timeout ladder — CALL_TIMEOUT_MS is 110s in prod
  #   /v1/approvals/{id}/call  the same call, replayed after an approval
  #   /mcp                     dispatches internally to /v1/actions/call
  #   /v1/uploads/{token}      streams up to UPLOAD_MAX_BYTES inside the handler
  #   /v1/downloads/{token}    may replay an upstream call to fetch the bytes
  #   /internal/metrics        our own scrape; the middleware sits outside it
  #   _unmatched               scanners and bad clients, not a route we own
  #
  # Written as explicit `!=` matchers rather than one `path!~"a|b|c"` regex so
  # the `{id}` / `{token}` braces never have to survive HCL -> PromQL -> RE2
  # escaping. Each string matches an axum 0.8 `MatchedPath`, so it must track
  # the literal `.route()` registration, braces included.
  gateway_path_exclusions = join(",", [
    "path!=\"/v1/events/stream\"",
    "path!=\"/v1/actions/call\"",
    "path!=\"/v1/approvals/{id}/call\"",
    "path!=\"/mcp\"",
    "path!=\"/v1/uploads/{token}\"",
    "path!=\"/v1/downloads/{token}\"",
    "path!=\"/internal/metrics\"",
    "path!=\"_unmatched\"",
  ])

  email_channel_ids = local.alerts_enabled ? [google_monitoring_notification_channel.email[0].id] : []

  # P0 channels: PagerDuty (if enabled) + email fallback.
  p0_channels = concat(
    local.alerts_enabled && var.pagerduty_enabled ? [google_monitoring_notification_channel.pagerduty[0].id] : [],
    local.email_channel_ids,
  )

  # P1/P2 channels: email only — user has no Slack.
  p1_channels = local.email_channel_ids
  p2_channels = local.email_channel_ids
}
