# State migrations.
#
# PR 200 created these resources without `count`. When this PR added a
# `count = local.alerts_enabled ? 1 : 0` gate to gate alerts on
# `alert_email`, every affected resource's state address changed from
# `name` to `name[0]`. Without these `moved` blocks, `tofu apply` on
# environments that were already running on PR 200 (i.e. `alert_email`
# already set) would destroy + recreate every alert and notification
# channel — a real monitoring outage during the apply window.
#
# Resources that already had a `count` (api_down, pagerduty, budget) keep
# their address and need no migration.

moved {
  from = google_monitoring_notification_channel.email
  to   = google_monitoring_notification_channel.email[0]
}

moved {
  from = google_monitoring_alert_policy.api_high_5xx
  to   = google_monitoring_alert_policy.api_high_5xx[0]
}

# `api_high_latency` is deliberately absent. It was removed outright rather
# than migrated: its Cloud Run `request_latencies` p99 was dominated by
# `/v1/events/stream`, whose SSE connections live a fixed 30s by design and so
# recorded 6x the 5s threshold on healthy traffic. That metric carries no route
# label, so it could not be filtered in place. Replaced by `api_slow_requests`
# in alerts_p1.tf; its `moved` block went with it.

moved {
  from = google_monitoring_alert_policy.api_high_cpu
  to   = google_monitoring_alert_policy.api_high_cpu[0]
}

moved {
  from = google_monitoring_alert_policy.api_high_memory
  to   = google_monitoring_alert_policy.api_high_memory[0]
}

moved {
  from = google_monitoring_alert_policy.db_high_cpu
  to   = google_monitoring_alert_policy.db_high_cpu[0]
}

moved {
  from = google_monitoring_alert_policy.db_high_disk
  to   = google_monitoring_alert_policy.db_high_disk[0]
}

moved {
  from = google_monitoring_alert_policy.background_task_stale
  to   = google_monitoring_alert_policy.background_task_stale[0]
}

moved {
  from = google_monitoring_alert_policy.oauth_refresh_failure_rate
  to   = google_monitoring_alert_policy.oauth_refresh_failure_rate[0]
}

moved {
  from = google_monitoring_alert_policy.webhook_failure_rate
  to   = google_monitoring_alert_policy.webhook_failure_rate[0]
}
