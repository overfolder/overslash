variable "project_id" {
  type = string
}

variable "cloud_run_sa_email" {
  type = string
}

# Database password
resource "google_secret_manager_secret" "db_password" {
  secret_id = "overslash-db-password"
  project   = var.project_id

  replication {
    auto {}
  }
}

# Generate initial DB password
resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db_password.result
}

# Secrets encryption key (AES-256 = 32 bytes = 64 hex chars)
resource "google_secret_manager_secret" "encryption_key" {
  secret_id = "overslash-encryption-key"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "random_id" "encryption_key" {
  byte_length = 32
}

resource "google_secret_manager_secret_version" "encryption_key" {
  secret      = google_secret_manager_secret.encryption_key.id
  secret_data = random_id.encryption_key.hex
}

# OAuth client ID (placeholder - user sets the real value)
resource "google_secret_manager_secret" "oauth_client_id" {
  secret_id = "overslash-oauth-client-id"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "oauth_client_id" {
  secret      = google_secret_manager_secret.oauth_client_id.id
  secret_data = "REPLACE_ME"
}

# OAuth client secret (placeholder - user sets the real value)
resource "google_secret_manager_secret" "oauth_client_secret" {
  secret_id = "overslash-oauth-client-secret"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "oauth_client_secret" {
  secret      = google_secret_manager_secret.oauth_client_secret.id
  secret_data = "REPLACE_ME"
}

output "db_password_secret_id" {
  value = google_secret_manager_secret.db_password.secret_id
}

output "encryption_key_secret_id" {
  value = google_secret_manager_secret.encryption_key.secret_id
}

output "oauth_client_id_secret_id" {
  value = google_secret_manager_secret.oauth_client_id.secret_id
}

output "oauth_client_secret_secret_id" {
  value = google_secret_manager_secret.oauth_client_secret.secret_id
}
