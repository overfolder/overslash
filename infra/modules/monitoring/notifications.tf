# Notification channels. Email is always present; PagerDuty is optional and
# only added to P0 routing when `pagerduty_enabled = true`.
#
# PagerDuty wiring: GCM's built-in `pagerduty` channel is hardcoded to the US
# endpoint, so we use a `webhook_tokenauth` channel pointing at PD's EU
# "Google Cloud Monitoring" integration URL, which natively accepts the GCM
# webhook payload. The integration key lives in Secret Manager.

resource "google_monitoring_notification_channel" "email" {
  count = local.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "${var.base_prefix} Email Alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

data "google_secret_manager_secret_version" "pagerduty_integration_key" {
  count   = local.alerts_enabled && var.pagerduty_enabled ? 1 : 0
  project = var.project_id
  secret  = var.pagerduty_secret_id
}

resource "google_monitoring_notification_channel" "pagerduty" {
  count = local.alerts_enabled && var.pagerduty_enabled ? 1 : 0

  project      = var.project_id
  display_name = "${var.base_prefix} PagerDuty (EU)"
  type         = "webhook_tokenauth"

  labels = {
    url = "https://events.eu.pagerduty.com/integration/${data.google_secret_manager_secret_version.pagerduty_integration_key[0].secret_data}/enqueue"
  }

  sensitive_labels {
    # PD GCM integration authenticates via the key in the URL; the bearer
    # header is ignored. webhook_tokenauth requires a non-empty token.
    auth_token = data.google_secret_manager_secret_version.pagerduty_integration_key[0].secret_data
  }
}
