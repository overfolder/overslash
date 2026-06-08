# P1 — email-only. Capacity, dependency health, business-process staleness.

# Cloud Run CPU > 90% for 10 min.
resource "google_monitoring_alert_policy" "api_high_cpu" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} API High CPU"
  combiner     = "OR"

  conditions {
    display_name = "CPU utilization > 90%"

    condition_threshold {
      filter          = "${local.api_filter} AND metric.type = \"run.googleapis.com/container/cpu/utilizations\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.9
      duration        = "600s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_PERCENTILE_99"
        cross_series_reducer = "REDUCE_MAX"
        group_by_fields      = ["resource.labels.service_name"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# Cloud Run memory > 85% for 10 min.
resource "google_monitoring_alert_policy" "api_high_memory" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} API High Memory"
  combiner     = "OR"

  conditions {
    display_name = "Memory utilization > 85%"

    condition_threshold {
      filter          = "${local.api_filter} AND metric.type = \"run.googleapis.com/container/memory/utilizations\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.85
      duration        = "600s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_PERCENTILE_99"
        cross_series_reducer = "REDUCE_MAX"
        group_by_fields      = ["resource.labels.service_name"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# Cloud SQL CPU > 80% for 10 min.
resource "google_monitoring_alert_policy" "db_high_cpu" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} Cloud SQL High CPU"
  combiner     = "OR"

  conditions {
    display_name = "DB CPU > 80%"

    condition_threshold {
      filter          = "${local.db_filter} AND metric.type = \"cloudsql.googleapis.com/database/cpu/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "600s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# Cloud SQL disk > 80% for 5 min.
resource "google_monitoring_alert_policy" "db_high_disk" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} Cloud SQL High Disk Usage"
  combiner     = "OR"

  conditions {
    display_name = "DB disk utilization > 80%"

    condition_threshold {
      filter          = "${local.db_filter} AND metric.type = \"cloudsql.googleapis.com/database/disk/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# Background-task silent-hang detection (PromQL). Sentry-style error tracking
# can't catch this — a wedged tokio loop just stops ticking. The exporter
# emits `overslash_background_task_last_success_timestamp{task=...}` on every
# successful tick; if (now - max(last_success)) > 5 min sustained for 10 min,
# something is stuck.
resource "google_monitoring_alert_policy" "background_task_stale" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} Background Task Stale"
  combiner     = "OR"

  conditions {
    display_name = "Background task last success > 5m for 10m"

    condition_prometheus_query_language {
      # Scope to the API Cloud Run service. The OTel collector populates
      # `job` from service.name (← faas.name), so this filters out any
      # accidental matches if another service ever emits a metric with the
      # same name.
      query               = <<-PROMQL
        (time() - max by (task) (overslash_background_task_last_success_timestamp{job="${var.api_service_name}",task=~"approval_expiry|execution_expiry|orphan_execution_reap|subagent_archive|subagent_purge|auto_bubble|rate_limit_evict|db_pool_poller|webhook_retry"})) > 300
      PROMQL
      duration            = "600s"
      evaluation_interval = "60s"
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }

  documentation {
    content   = "An overslash-api background task has not reported a successful tick in over 5 minutes (sustained for 10 minutes). The tokio loop may be wedged — Sentry/Cloud Logging will NOT catch this. Check Cloud Run logs for the `overslash-api` instance and look at the `task` label on the firing series."
    mime_type = "text/markdown"
  }
}

# OAuth refresh failure rate > 10% over 15 min. Refresh failures are the most
# common reason connections silently stop working.
resource "google_monitoring_alert_policy" "oauth_refresh_failure_rate" {
  count = local.alerts_enabled && var.oauth_refresh_alert_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} OAuth Refresh Failure Rate"
  combiner     = "OR"

  conditions {
    display_name = "OAuth refresh failure ratio > 10%"

    condition_prometheus_query_language {
      query               = <<-PROMQL
        sum(rate(overslash_oauth_events_total{flow="refresh",status="failure"}[15m]))
          /
        clamp_min(sum(rate(overslash_oauth_events_total{flow="refresh"}[15m])), 1)
        > 0.10
      PROMQL
      duration            = "900s"
      evaluation_interval = "60s"
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# Upstream error rate > 20% over 15 min — a service Overslash *calls* is
# failing (HTTP 5xx, or an MCP tool returning in-band `is_error: true`).
# These never show on the gateway's own request_count: HTTP-mode actions
# pass the upstream status through inside a 200 envelope, and MCP errors are
# in-band behind an outer 200 — so without this alert an upstream outage
# looks like 100% success. P1 not P0: Overslash itself is up (its own 5xx
# pages via the P0 alert). The 20% bar is deliberately higher than the
# oauth/webhook ratios — occasional tool errors and upstream 5xx are
# semi-normal; this should fire on outages, not flaky single calls.
resource "google_monitoring_alert_policy" "upstream_error_rate" {
  count = local.alerts_enabled && var.upstream_error_alert_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} Upstream Error Rate"
  combiner     = "OR"

  conditions {
    display_name = "Upstream error ratio > 20%"

    condition_prometheus_query_language {
      query               = <<-PROMQL
        sum(rate(overslash_upstream_responses_total{job="${var.api_service_name}",status_class=~"5xx|error"}[15m]))
          /
        clamp_min(sum(rate(overslash_upstream_responses_total{job="${var.api_service_name}"}[15m])), 1)
        > 0.20
      PROMQL
      duration            = "900s"
      evaluation_interval = "60s"
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }

  documentation {
    content   = "More than 20% of upstream responses over the last 15 minutes were failures — HTTP 5xx from an upstream API or in-band MCP tool errors (`is_error: true`). This is an *upstream* outage, not Overslash's own errors (those page via the P0 5xx alert). Break down `overslash_upstream_responses_total` by `template_key` (the 'Upstream Error Ratio by Template' chart on the Actions & OAuth dashboard) to find the failing service."
    mime_type = "text/markdown"
  }
}

# Webhook terminal-failure rate > 5% over 30 min.
resource "google_monitoring_alert_policy" "webhook_failure_rate" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} Webhook Delivery Failure Rate"
  combiner     = "OR"

  conditions {
    display_name = "Webhook terminal failure ratio > 5%"

    condition_prometheus_query_language {
      query               = <<-PROMQL
        sum(rate(overslash_webhook_deliveries_total{status="failed",final="true"}[30m]))
          /
        clamp_min(sum(rate(overslash_webhook_deliveries_total{final="true"}[30m])), 1)
        > 0.05
      PROMQL
      duration            = "1800s"
      evaluation_interval = "60s"
    }
  }

  notification_channels = local.p1_channels

  alert_strategy {
    auto_close = "604800s"
  }
}
