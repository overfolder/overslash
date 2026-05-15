# Public uptime check on the API's /health endpoint. Only created when an
# api_domain is configured — without one there's no externally reachable host.

resource "google_monitoring_uptime_check_config" "api_health" {
  count = var.api_domain != "" ? 1 : 0

  project      = var.project_id
  display_name = "${var.base_prefix}-api-health"
  timeout      = "10s"
  period       = "60s"

  http_check {
    path         = "/health"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.api_domain
    }
  }

  checker_type = "STATIC_IP_CHECKERS"
}
