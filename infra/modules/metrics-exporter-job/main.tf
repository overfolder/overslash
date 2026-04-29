# Cloud Run Job + Cloud Scheduler trigger for the business-metrics exporter.
#
# The job runs on a 5-minute Cloud Scheduler cron, queries Postgres in
# parallel, and pushes ~15 time-series to Cloud Monitoring. It uses the
# Cloud Run service account, which must already have:
#   - roles/cloudsql.client (Cloud SQL connector)
#   - roles/monitoring.metricWriter (timeSeries.create)

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "service_account_email" {
  type        = string
  description = "Service account that runs the job. Must have monitoring.metricWriter and cloudsql.client roles."
}

variable "scheduler_sa_email" {
  type        = string
  description = "Service account Cloud Scheduler uses to invoke the job. Must have run.invoker on the job."
}

variable "image" {
  type        = string
  description = "Fully-qualified Artifact Registry image URI for the exporter."
}

variable "cloud_sql_connection_name" {
  type = string
}

variable "db_user" {
  type = string
}

variable "db_name" {
  type = string
}

variable "db_password_secret_id" {
  type        = string
  description = "Secret Manager secret holding the DB password (mounted as DATABASE_PASSWORD)."
}

variable "schedule_cron" {
  type        = string
  default     = "*/5 * * * *"
  description = "Cron expression for the scheduler. Defaults to every 5 minutes."
}

variable "cpu" {
  type    = string
  default = "1"
}

variable "memory" {
  type    = string
  default = "256Mi"
}

variable "task_timeout" {
  type        = string
  default     = "120s"
  description = "Per-execution timeout. Generous compared to the typical run (~1s) so a transient DB hiccup doesn't fail the job."
}

resource "google_cloud_run_v2_job" "exporter" {
  name     = "${var.base_prefix}-metrics-exporter"
  location = var.region
  project  = var.project_id

  template {
    template {
      service_account = var.service_account_email
      timeout         = var.task_timeout

      max_retries = 1

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [var.cloud_sql_connection_name]
        }
      }

      containers {
        image = var.image

        resources {
          limits = {
            cpu    = var.cpu
            memory = var.memory
          }
        }

        env {
          name  = "GCP_PROJECT_ID"
          value = var.project_id
        }
        env {
          name  = "GCP_REGION"
          value = var.region
        }
        env {
          name  = "LOG_FORMAT"
          value = "json"
        }
        env {
          name = "DATABASE_URL"
          # Cloud SQL Unix socket connection string — same shape used by the
          # API service.
          value = "postgresql://${var.db_user}@localhost/${var.db_name}?host=/cloudsql/${var.cloud_sql_connection_name}"
        }
        env {
          name = "DATABASE_PASSWORD"
          value_source {
            secret_key_ref {
              secret  = var.db_password_secret_id
              version = "latest"
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }
    }
  }

  lifecycle {
    # The Cloud Build trigger updates the image tag on each deploy; we want
    # terraform to leave that alone so successive plans don't fight the CD
    # pipeline. Same approach as the API service.
    ignore_changes = [
      template[0].template[0].containers[0].image,
    ]
  }
}

resource "google_cloud_scheduler_job" "tick" {
  name             = "${var.base_prefix}-metrics-exporter-tick"
  project          = var.project_id
  region           = var.region
  schedule         = var.schedule_cron
  time_zone        = "Etc/UTC"
  attempt_deadline = "180s"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.exporter.name}:run"

    oauth_token {
      service_account_email = var.scheduler_sa_email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  retry_config {
    retry_count = 1
  }
}

output "job_name" {
  value = google_cloud_run_v2_job.exporter.name
}

output "scheduler_job_name" {
  value = google_cloud_scheduler_job.tick.name
}
