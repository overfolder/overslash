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

# --- Google LOGIN OAuth client (Sign-in with Google, openid/email/profile).
#     Legacy resource name `oauth_client_*` kept to preserve Terraform state and
#     the prod-populated secret value. Feeds `GOOGLE_AUTH_CLIENT_ID/_SECRET`. ---

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

  lifecycle {
    ignore_changes = [secret_data]
  }
}

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

  lifecycle {
    ignore_changes = [secret_data]
  }
}

# --- Google SERVICES OAuth client (Calendar/Drive/Gmail, sensitive scopes).
#     Overslash-managed default so the cloud instance is turnkey; orgs can
#     override per-org via POST /v1/org/oauth-credentials/google. Feeds
#     `OAUTH_GOOGLE_CLIENT_ID/_SECRET` — requires
#     `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1` on Cloud Run. ---

resource "google_secret_manager_secret" "google_services_client_id" {
  secret_id = "${var.base_prefix}-google-services-client-id"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "google_services_client_id" {
  secret      = google_secret_manager_secret.google_services_client_id.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

resource "google_secret_manager_secret" "google_services_client_secret" {
  secret_id = "${var.base_prefix}-google-services-client-secret"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "google_services_client_secret" {
  secret      = google_secret_manager_secret.google_services_client_secret.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
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

output "google_services_client_id_secret_id" {
  value = google_secret_manager_secret.google_services_client_id.secret_id
}

output "google_services_client_secret_secret_id" {
  value = google_secret_manager_secret.google_services_client_secret.secret_id
}
