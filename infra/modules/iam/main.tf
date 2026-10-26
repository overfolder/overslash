variable "project_id" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "enable_shortener" {
  type    = bool
  default = false
}

variable "enable_overfwd" {
  type    = bool
  default = false
}

# --- Runtime service accounts (CASA 3.1.1, 6.7.1) ---
#
# One identity per workload, so each reads only its own secrets. None holds a
# project-wide Secret Manager role: the API's grant is scoped by secret name
# (modules/secret-manager), the others are granted secret by secret in the
# module that runs them. See docs/compliance/casa/secrets-access-policy.md.
#
# `-run` is the API's. It keeps its historical name: renaming a service account
# replaces it, and every binding and audit filter keyed on the email with it.

resource "google_service_account" "cloud_run" {
  account_id   = "${var.base_prefix}-run"
  display_name = "${var.base_prefix} Cloud Run"
  project      = var.project_id
}

resource "google_service_account" "metrics_exporter" {
  account_id   = "${var.base_prefix}-exporter"
  display_name = "${var.base_prefix} metrics exporter job"
  project      = var.project_id
}

resource "google_service_account" "shortener" {
  count        = var.enable_shortener ? 1 : 0
  account_id   = "${var.base_prefix}-shortener"
  display_name = "${var.base_prefix} oversla.sh shortener"
  project      = var.project_id
}

resource "google_service_account" "overfwd" {
  count        = var.enable_overfwd ? 1 : 0
  account_id   = "${var.base_prefix}-overfwd"
  display_name = "${var.base_prefix} overfwd Mailbox Gateway"
  project      = var.project_id
}

resource "google_project_iam_member" "cloud_run_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# The API's OTel sidecar writes metrics through this.
resource "google_project_iam_member" "cloud_run_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# The exporter reaches Postgres through the Auth Proxy volume and calls
# monitoring.googleapis.com/v3/projects/{id}/timeSeries:create. Its one secret
# (the DB password) is granted in modules/metrics-exporter-job.
resource "google_project_iam_member" "metrics_exporter_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.metrics_exporter.email}"
}

resource "google_project_iam_member" "metrics_exporter_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.metrics_exporter.email}"
}

# --- Cloud Build service account ---

resource "google_service_account" "cloud_build" {
  account_id   = "${var.base_prefix}-build"
  display_name = "${var.base_prefix} Cloud Build"
  project      = var.project_id
}

resource "google_project_iam_member" "cloud_build_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_project_iam_member" "cloud_build_run_developer" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_project_iam_member" "cloud_build_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_project_iam_member" "cloud_build_sa_user" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

# --- Scheduler service account (for night shutdown) ---

resource "google_service_account" "scheduler" {
  account_id   = "${var.base_prefix}-scheduler"
  display_name = "${var.base_prefix} Cloud Scheduler"
  project      = var.project_id
}

# Its Cloud SQL permission (start/stop only, on the one instance) is granted
# in modules/infra-scheduler, so it exists only where night shutdown does.

# Lets Cloud Scheduler invoke the metrics-exporter Cloud Run Job via the
# `:run` REST endpoint. Project-wide grant matches how the existing
# infra-scheduler invokes other resources.
resource "google_project_iam_member" "scheduler_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.scheduler.email}"
}

output "cloud_run_sa_email" {
  value = google_service_account.cloud_run.email
}

output "cloud_run_sa_id" {
  value = google_service_account.cloud_run.id
}

output "cloud_build_sa_email" {
  value = google_service_account.cloud_build.email
}

output "cloud_build_sa_id" {
  value = google_service_account.cloud_build.id
}

output "metrics_exporter_sa_email" {
  value = google_service_account.metrics_exporter.email
}

output "shortener_sa_email" {
  value = try(google_service_account.shortener[0].email, "")
}

output "overfwd_sa_email" {
  value = try(google_service_account.overfwd[0].email, "")
}

output "scheduler_sa_email" {
  value = google_service_account.scheduler.email
}
