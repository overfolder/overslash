variable "project_id" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "cloud_run_sa_email" {
  type = string
}

# --- Database password ---

resource "google_secret_manager_secret" "db_password" {
  secret_id = "${var.base_prefix}-db-password"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db_password.result
}

# --- Encryption key (AES-256 = 32 bytes = 64 hex chars) ---

resource "google_secret_manager_secret" "encryption_key" {
  secret_id = "${var.base_prefix}-encryption-key"
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

# --- Signing key (HMAC for API tokens = 32 bytes = 64 hex chars) ---

resource "google_secret_manager_secret" "signing_key" {
  secret_id = "${var.base_prefix}-signing-key"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "random_id" "signing_key" {
  byte_length = 32
}

resource "google_secret_manager_secret_version" "signing_key" {
  secret      = google_secret_manager_secret.signing_key.id
  secret_data = random_id.signing_key.hex
}

# --- OAuth client ID (placeholder - set real value via gcloud) ---

resource "google_secret_manager_secret" "oauth_client_id" {
  secret_id = "${var.base_prefix}-oauth-client-id"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "oauth_client_id" {
  secret      = google_secret_manager_secret.oauth_client_id.id
  secret_data = "REPLACE_ME"
}

# --- OAuth client secret (placeholder - set real value via gcloud) ---

resource "google_secret_manager_secret" "oauth_client_secret" {
  secret_id = "${var.base_prefix}-oauth-client-secret"
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

output "db_password_value" {
  value     = random_password.db_password.result
  sensitive = true
}

output "encryption_key_secret_id" {
  value = google_secret_manager_secret.encryption_key.secret_id
}

output "signing_key_secret_id" {
  value = google_secret_manager_secret.signing_key.secret_id
}

output "oauth_client_id_secret_id" {
  value = google_secret_manager_secret.oauth_client_id.secret_id
}

output "oauth_client_secret_secret_id" {
  value = google_secret_manager_secret.oauth_client_secret.secret_id
}
