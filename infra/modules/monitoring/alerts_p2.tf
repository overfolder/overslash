# P2 — informational, email only.

# Gateway 4xx ratio spike. 4xx is dominated by legitimate client errors —
# validation failures, permission denials, and rate limits all map to 4xx by
# design — so an absolute-rate or low-ratio threshold would be constant
# noise. A 30% ratio sustained for 10 minutes flags a regime change instead:
# a deploy that rejects valid requests, a broken auth path 401/403-ing
# broadly, or a misbehaving client hammering the API.
resource "google_monitoring_alert_policy" "api_high_4xx" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P2] ${var.base_prefix} API High 4xx Rate"
  combiner     = "OR"

  conditions {
    display_name = "4xx error rate > 30%"

    condition_threshold {
      filter          = "${local.api_filter} AND metric.type = \"run.googleapis.com/request_count\" AND metric.labels.response_code_class = \"4xx\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.30
      duration        = "600s"

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

  notification_channels = local.p2_channels

  alert_strategy {
    auto_close = "604800s"
  }
}

# Monthly billing budget at 50% / 80% / 100%. Skipped when the project isn't
# linked to a billing account.
resource "google_billing_budget" "monthly" {
  count = local.alerts_enabled && var.billing_account_id != "" ? 1 : 0

  billing_account = var.billing_account_id
  display_name    = "${var.base_prefix} Monthly Budget"

  budget_filter {
    projects = ["projects/${data.google_project.current.number}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = var.monthly_budget_usd
    }
  }

  threshold_rules {
    threshold_percent = 0.5
    spend_basis       = "CURRENT_SPEND"
  }
  threshold_rules {
    threshold_percent = 0.8
    spend_basis       = "CURRENT_SPEND"
  }
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "CURRENT_SPEND"
  }

  # Without this block, threshold notifications go only to billing-admin
  # IAM members. With it, they fan out to our email channel too — which is
  # what the user actually reads.
  all_updates_rule {
    monitoring_notification_channels = local.p2_channels
    disable_default_iam_recipients   = false
  }
}
