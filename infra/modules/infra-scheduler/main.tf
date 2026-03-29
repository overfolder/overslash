variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "cloud_sql_instance_name" {
  type = string
}

variable "stop_cron" {
  description = "Cron to stop Cloud SQL (Europe/Madrid)"
  type        = string
  default     = "0 23 * * *"
}

variable "start_cron" {
  description = "Cron to start Cloud SQL (Europe/Madrid)"
  type        = string
  default     = "0 7 * * 1-5"
}

variable "scheduler_sa_email" {
  type = string
}

# Stop Cloud SQL at night — sets activation policy to NEVER
resource "google_cloud_scheduler_job" "stop_db" {
  name     = "${var.base_prefix}-db-stop"
  project  = var.project_id
  region   = var.region
  schedule = var.stop_cron

  time_zone   = "Europe/Madrid"
  description = "Stop Cloud SQL instance at night to save cost"

  http_target {
    uri         = "https://sqladmin.googleapis.com/v1/projects/${var.project_id}/instances/${var.cloud_sql_instance_name}"
    http_method = "PATCH"
    body        = base64encode(jsonencode({ settings = { activationPolicy = "NEVER" } }))

    headers = {
      "Content-Type" = "application/json"
    }

    oauth_token {
      service_account_email = var.scheduler_sa_email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  retry_config {
    retry_count = 1
  }
}

# Start Cloud SQL in the morning — sets activation policy to ALWAYS
resource "google_cloud_scheduler_job" "start_db" {
  name     = "${var.base_prefix}-db-start"
  project  = var.project_id
  region   = var.region
  schedule = var.start_cron

  time_zone   = "Europe/Madrid"
  description = "Start Cloud SQL instance in the morning"

  http_target {
    uri         = "https://sqladmin.googleapis.com/v1/projects/${var.project_id}/instances/${var.cloud_sql_instance_name}"
    http_method = "PATCH"
    body        = base64encode(jsonencode({ settings = { activationPolicy = "ALWAYS" } }))

    headers = {
      "Content-Type" = "application/json"
    }

    oauth_token {
      service_account_email = var.scheduler_sa_email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  retry_config {
    retry_count = 1
  }
}
