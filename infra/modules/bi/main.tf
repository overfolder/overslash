# BI surface: BigQuery federated queries over the curated `bi` schema in Cloud
# SQL (migration 126). See docs/runbooks/bi.md.
#
# Nothing is copied out of Postgres: each BigQuery view below is an
# EXTERNAL_QUERY that runs against the live instance as the `bi` login role.
# The API creates that role at boot (overslash_db::bi) from the password
# generated here, so it holds only `bi_reader`. A google_sql_user would
# instead join cloudsqlsuperuser, which the app can't revoke. Cloud SQL on private
# IP is reachable because the instance sets
# enable_private_path_for_google_cloud_services.

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "sql_connection_name" {
  description = "Cloud SQL connection name (project:region:instance)."
  type        = string
}

variable "sql_database" {
  type = string
}

variable "bi_viewers" {
  description = "IAM members (e.g. user:a@b.com) allowed to query the BI dataset. Project owners already can."
  type        = list(string)
  default     = []
}

locals {
  # Every `bi.*` Postgres view exposed to BigQuery. Adding one = a migration
  # creating the view + its name here.
  views = ["orgs", "org_members", "org_summary"]

  # EXTERNAL_QUERY wants project.location.connection_id, not the resource id.
  external_connection = "${var.project_id}.${var.region}.${google_bigquery_connection.pg.connection_id}"
}

# --- Password for the `bi` role (created by the API, not here) ---

resource "random_password" "bi" {
  length  = 32
  special = false
}

resource "google_secret_manager_secret" "bi_db_password" {
  secret_id = "${var.base_prefix}-bi-db-password"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "bi_db_password" {
  secret      = google_secret_manager_secret.bi_db_password.id
  secret_data = random_password.bi.result
}

# --- BigQuery connection ---

resource "google_bigquery_connection" "pg" {
  connection_id = "${var.base_prefix}-pg"
  project       = var.project_id
  location      = var.region
  friendly_name = "Overslash Postgres (bi schema)"

  cloud_sql {
    instance_id = var.sql_connection_name
    database    = var.sql_database
    type        = "POSTGRES"
    credential {
      username = "bi"
      password = random_password.bi.result
    }
  }
}

resource "google_project_iam_member" "connection_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_bigquery_connection.pg.cloud_sql[0].service_account_id}"
}

# --- Dataset + views ---

resource "google_bigquery_dataset" "bi" {
  dataset_id  = "overslash_bi"
  project     = var.project_id
  location    = var.region
  description = "Live views over the Overslash `bi` Postgres schema (EXTERNAL_QUERY). See docs/runbooks/bi.md."
}

resource "google_bigquery_table" "view" {
  for_each = toset(local.views)

  dataset_id          = google_bigquery_dataset.bi.dataset_id
  project             = var.project_id
  table_id            = each.key
  deletion_protection = false

  view {
    query          = "SELECT * FROM EXTERNAL_QUERY(\"${local.external_connection}\", \"SELECT * FROM bi.${each.key}\")"
    use_legacy_sql = false
  }
}

# --- Who can query ---

resource "google_project_iam_member" "viewer_job_user" {
  for_each = toset(var.bi_viewers)
  project  = var.project_id
  role     = "roles/bigquery.jobUser"
  member   = each.key
}

resource "google_bigquery_dataset_iam_member" "viewer_data" {
  for_each   = toset(var.bi_viewers)
  project    = var.project_id
  dataset_id = google_bigquery_dataset.bi.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = each.key
}

resource "google_bigquery_connection_iam_member" "viewer_connection" {
  for_each      = toset(var.bi_viewers)
  project       = var.project_id
  location      = var.region
  connection_id = google_bigquery_connection.pg.connection_id
  role          = "roles/bigquery.connectionUser"
  member        = each.key
}

output "dataset_id" {
  value = google_bigquery_dataset.bi.dataset_id
}

output "db_password_secret_id" {
  description = "Mounted into Cloud Run as OVERSLASH_BI_DB_PASSWORD."
  value       = google_secret_manager_secret.bi_db_password.secret_id
}

output "connection" {
  value = local.external_connection
}
