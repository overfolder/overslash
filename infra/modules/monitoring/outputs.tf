output "email_channel_id" {
  value = local.alerts_enabled ? google_monitoring_notification_channel.email[0].id : ""
}

output "pagerduty_channel_id" {
  value = local.alerts_enabled && var.pagerduty_integration_key != "" ? google_monitoring_notification_channel.pagerduty[0].id : ""
}

output "uptime_check_id" {
  value = var.api_domain != "" ? google_monitoring_uptime_check_config.api_health[0].uptime_check_id : ""
}
