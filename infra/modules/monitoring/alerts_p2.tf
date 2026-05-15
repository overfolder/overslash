# P2 — informational, email only.

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
