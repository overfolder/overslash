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

# Secret rotation (CASA 6.7.1; docs/runbooks/secret-rotation.md). The metrics
# exporter sweeps Secret Manager metadata hourly and writes each secret's
# overdue days, zeros included. The series are hourly, so the alignment period
# is two ticks wide: a single missed tick must not read as a recovery. P2,
# because a secret past its period is a schedule slip and not an exposure; the
# exposure path is `[P1] Unexpected Secret Access`.
#
# A secret stays overdue until a new version exists, so the incident stays open
# until then. The absence condition covers the sweep itself failing, which the
# exporter logs and skips rather than losing every business metric.
resource "google_monitoring_alert_policy" "secret_rotation_overdue" {
  count = local.alerts_enabled && var.secret_rotation_alert_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P2] ${var.base_prefix} Secret Rotation Overdue"
  combiner     = "OR"

  conditions {
    display_name = "Latest secret version older than its rotation period"

    condition_threshold {
      filter          = "${local.business_filter} AND metric.type = \"custom.googleapis.com/overslash/business/secret_rotation_overdue_days\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "7200s"
        per_series_aligner   = "ALIGN_MAX"
        cross_series_reducer = "REDUCE_MAX"
        group_by_fields      = ["metric.labels.secret"]
      }

      trigger {
        count = 1
      }
    }
  }

  conditions {
    display_name = "Secret with no rotation class, period or enabled version"

    condition_threshold {
      filter          = "${local.business_filter} AND metric.type = \"custom.googleapis.com/overslash/business/secret_rotation_unmeasured\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "7200s"
        per_series_aligner   = "ALIGN_MAX"
        cross_series_reducer = "REDUCE_MAX"
      }

      trigger {
        count = 1
      }
    }
  }

  conditions {
    display_name = "Secret rotation sweep not reporting for 3h"

    condition_absent {
      filter   = "${local.business_filter} AND metric.type = \"custom.googleapis.com/overslash/business/secret_rotation_unmeasured\""
      duration = "10800s"

      aggregations {
        alignment_period     = "3600s"
        per_series_aligner   = "ALIGN_MAX"
        cross_series_reducer = "REDUCE_COUNT"
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

  documentation {
    content   = "A secret's newest enabled version is older than its rotation period; the `secret` label names it. Rotate it per its class in docs/compliance/casa/secrets-access-policy.md. A non-zero `secret_rotation_unmeasured` means a secret the sweep cannot age: the exporter's `secret cannot be measured` WARN logs name it and say why. If the absence condition fired, the sweep itself failed: look for `Secret rotation sweep failed` in the metrics-exporter job logs."
    mime_type = "text/markdown"
  }
}

# The reminder half: Secret Manager reached a secret's `next_rotation_time`. It
# fires while a SECRET_ROTATE event is waiting on the subscription, so it clears
# when the operator pulls it, or by itself after the 7-day message retention.
resource "google_monitoring_alert_policy" "secret_rotation_due" {
  count = local.alerts_enabled && var.secret_rotation_alert_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P2] ${var.base_prefix} Secret Rotation Due"
  combiner     = "OR"

  conditions {
    display_name = "SECRET_ROTATE event waiting"

    condition_threshold {
      filter          = "resource.type = \"pubsub_subscription\" AND resource.labels.subscription_id = \"${var.secret_rotation_subscription_id}\" AND metric.type = \"pubsub.googleapis.com/subscription/num_undelivered_messages\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MAX"
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

  documentation {
    content   = "A secret reached its scheduled rotation date. See which: `gcloud pubsub subscriptions pull ${var.secret_rotation_subscription_id} --project=${var.project_id} --auto-ack --limit=20 --format=json`, then read `attributes.secretId`. Pulling clears this alert. Rotate per the secret's class in docs/compliance/casa/secrets-access-policy.md."
    mime_type = "text/markdown"
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
