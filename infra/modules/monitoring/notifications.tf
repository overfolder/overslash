# Notification channels. Email is always present; PagerDuty is optional and
# only added to P0 routing when an integration key is supplied.

resource "google_monitoring_notification_channel" "email" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "${var.base_prefix} Email Alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_notification_channel" "pagerduty" {
  count = local.alerts_enabled && var.pagerduty_integration_key != "" ? 1 : 0

  project      = var.project_id
  display_name = "${var.base_prefix} PagerDuty"
  type         = "pagerduty"

  sensitive_labels {
    auth_token = var.pagerduty_integration_key
  }
}
