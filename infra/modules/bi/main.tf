# BI surface: BigQuery federated queries over prod Postgres. See
# docs/runbooks/bi.md.
#
# Nothing is copied out of Postgres. Each BigQuery view is an EXTERNAL_QUERY
# whose inner SQL is a file under sql/, run live against the instance as the
# Postgres role `bi`. The API creates that role at boot (overslash_db::bi)
# from the password generated here, and grants it SELECT on an allow-list of
# columns only. A google_sql_user would join cloudsqlsuperuser instead, which
# the app can't revoke. Adding a report = a new sql/<name>.sql + tofu apply;
# the crate test bi_views runs every file as `bi` in CI.

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
  # sql/<name>.sql becomes BigQuery view overslash_bi.<name>.
  views = { for f in fileset("${path.module}/sql", "*.sql") : trimsuffix(f, ".sql") => file("${path.module}/sql/${f}") }

  # EXTERNAL_QUERY wants project.location.connection_id, not the resource id.
  external_connection = "${var.project_id}.${var.region}.${google_bigquery_connection.pg.connection_id}"
}

# --- Password for the `bi` role (the API creates the role) ---

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
  friendly_name = "Overslash Postgres (as role bi)"

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
  description = "Live EXTERNAL_QUERY views over Overslash Postgres, read as role bi. See docs/runbooks/bi.md."
}

resource "google_bigquery_table" "view" {
  for_each = local.views

  dataset_id          = google_bigquery_dataset.bi.dataset_id
  project             = var.project_id
  table_id            = each.key
  deletion_protection = false

  view {
    query          = "SELECT * FROM EXTERNAL_QUERY(\"${local.external_connection}\", \"\"\"${each.value}\"\"\")"
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
