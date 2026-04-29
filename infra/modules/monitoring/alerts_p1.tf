# P1 — email-only. Capacity, dependency health, business-process staleness.

# Cloud Run CPU > 90% for 10 min.
resource "google_monitoring_alert_policy" "api_high_cpu" {
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
  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} Background Task Stale"
  combiner     = "OR"

  conditions {
    display_name = "Background task last success > 5m for 10m"

    condition_prometheus_query_language {
      query               = <<-PROMQL
        (time() - max by (task) (overslash_background_task_last_success_timestamp{task=~"approval_expiry|execution_expiry|orphan_execution_reap|subagent_archive|subagent_purge|auto_bubble|rate_limit_evict|db_pool_poller|webhook_retry"})) > 300
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

# Webhook terminal-failure rate > 5% over 30 min.
resource "google_monitoring_alert_policy" "webhook_failure_rate" {
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
