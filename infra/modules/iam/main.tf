variable "project_id" {
  type = string
}

variable "base_prefix" {
  type = string
}

# --- Cloud Run service account ---

resource "google_service_account" "cloud_run" {
  account_id   = "${var.base_prefix}-run"
  display_name = "${var.base_prefix} Cloud Run"
  project      = var.project_id
}

resource "google_project_iam_member" "cloud_run_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
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

resource "google_project_iam_member" "scheduler_sql_admin" {
  project = var.project_id
  role    = "roles/cloudsql.admin"
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

output "scheduler_sa_email" {
  value = google_service_account.scheduler.email
}
