# P0 — pages on-call (PagerDuty if configured, email always).

# API down: uptime check fails 2 consecutive 60s probes.
resource "google_monitoring_alert_policy" "api_down" {
  count = var.api_domain != "" ? 1 : 0

  project      = var.project_id
  display_name = "[P0] ${var.base_prefix} API Down"
  combiner     = "OR"

  conditions {
    display_name = "API health check failing"

    condition_threshold {
      filter          = "resource.type = \"uptime_url\" AND metric.type = \"monitoring.googleapis.com/uptime_check/check_passed\" AND metric.labels.check_id = \"${google_monitoring_uptime_check_config.api_health[0].uptime_check_id}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      duration        = "120s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_NEXT_OLDER"
        cross_series_reducer = "REDUCE_COUNT_FALSE"
        group_by_fields      = ["resource.labels.project_id"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.p0_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# 5xx ratio > 1% over 5 min.
resource "google_monitoring_alert_policy" "api_high_5xx" {
  project      = var.project_id
  display_name = "[P0] ${var.base_prefix} API High 5xx Rate"
  combiner     = "OR"

  conditions {
    display_name = "5xx error rate > 1%"

    condition_threshold {
      filter          = "${local.api_filter} AND metric.type = \"run.googleapis.com/request_count\" AND metric.labels.response_code_class = \"5xx\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.01
      duration        = "300s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.labels.service_name"]
      }

      denominator_filter = "${local.api_filter} AND metric.type = \"run.googleapis.com/request_count\""

      denominator_aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.labels.service_name"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.p0_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# p99 latency > 5s over 5 min.
resource "google_monitoring_alert_policy" "api_high_latency" {
  project      = var.project_id
  display_name = "[P0] ${var.base_prefix} API High P99 Latency"
  combiner     = "OR"

  conditions {
    display_name = "P99 latency > 5s"

    condition_threshold {
      filter          = "${local.api_filter} AND metric.type = \"run.googleapis.com/request_latencies\""
      comparison      = "COMPARISON_GT"
      threshold_value = 5000 # ms
      duration        = "300s"

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

  notification_channels = local.p0_channels

  alert_strategy {
    auto_close = "604800s"
  }
}
