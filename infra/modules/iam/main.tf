variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

# Service account for Cloud Run
resource "google_service_account" "cloud_run" {
  account_id   = "overslash-cloud-run"
  display_name = "Overslash Cloud Run Service Account"
  project      = var.project_id
}

# Cloud Run SA needs: Secret Manager access, Cloud SQL client, logging
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

# Service account for Cloud Build
resource "google_service_account" "cloud_build" {
  account_id   = "overslash-cloud-build"
  display_name = "Overslash Cloud Build Service Account"
  project      = var.project_id
}

# Cloud Build SA needs: Artifact Registry writer, Cloud Run deployer, log writer
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
