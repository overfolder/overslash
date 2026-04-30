# Five dashboards rendered from .json.tftpl templates.
#
# GCP enriches dashboard JSON with server-side defaults (targetAxis, name,
# etc.), so a vanilla `tofu plan` shows perpetual drift. The fix:
# `ignore_changes = [dashboard_json]` plus `replace_triggered_by` on a
# `terraform_data` whose input is the template's file hash. Dashboards
# only recreate when the template actually changes on disk.

locals {
  # Filters contain literal double quotes (GCP Monitoring filter syntax).
  # They are interpolated into JSON string values inside the dashboard
  # templates, so the embedded quotes must be JSON-escaped or the rendered
  # output is invalid JSON.
  dashboard_vars = {
    display_prefix  = var.base_prefix
    api_filter      = replace(local.api_filter, "\"", "\\\"")
    db_filter       = replace(local.db_filter, "\"", "\\\"")
    business_filter = replace(local.business_filter, "\"", "\\\"")
    uptime_check_id = var.api_domain != "" ? google_monitoring_uptime_check_config.api_health[0].uptime_check_id : ""
  }
}

resource "terraform_data" "dashboard_hash" {
  for_each = {
    overview          = "${path.module}/dashboards/overview.json.tftpl"
    api_use           = "${path.module}/dashboards/api-use.json.tftpl"
    cloudsql_use      = "${path.module}/dashboards/cloudsql-use.json.tftpl"
    business          = "${path.module}/dashboards/business.json.tftpl"
    actions_and_oauth = "${path.module}/dashboards/actions-and-oauth.json.tftpl"
  }
  input = sha256(templatefile(each.value, local.dashboard_vars))
}

resource "google_monitoring_dashboard" "overview" {
  project        = var.project_id
  dashboard_json = templatefile("${path.module}/dashboards/overview.json.tftpl", local.dashboard_vars)

  lifecycle {
    ignore_changes       = [dashboard_json]
    replace_triggered_by = [terraform_data.dashboard_hash["overview"]]
  }
}

resource "google_monitoring_dashboard" "api_use" {
  project        = var.project_id
  dashboard_json = templatefile("${path.module}/dashboards/api-use.json.tftpl", local.dashboard_vars)

  lifecycle {
    ignore_changes       = [dashboard_json]
    replace_triggered_by = [terraform_data.dashboard_hash["api_use"]]
  }
}

resource "google_monitoring_dashboard" "cloudsql_use" {
  project        = var.project_id
  dashboard_json = templatefile("${path.module}/dashboards/cloudsql-use.json.tftpl", local.dashboard_vars)

  lifecycle {
    ignore_changes       = [dashboard_json]
    replace_triggered_by = [terraform_data.dashboard_hash["cloudsql_use"]]
  }
}

resource "google_monitoring_dashboard" "business" {
  project        = var.project_id
  dashboard_json = templatefile("${path.module}/dashboards/business.json.tftpl", local.dashboard_vars)

  lifecycle {
    ignore_changes       = [dashboard_json]
    replace_triggered_by = [terraform_data.dashboard_hash["business"]]
  }
}

resource "google_monitoring_dashboard" "actions_and_oauth" {
  project        = var.project_id
  dashboard_json = templatefile("${path.module}/dashboards/actions-and-oauth.json.tftpl", local.dashboard_vars)

  lifecycle {
    ignore_changes       = [dashboard_json]
    replace_triggered_by = [terraform_data.dashboard_hash["actions_and_oauth"]]
  }
}
