variable "project_id" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "cloud_run_sa_email" {
  type = string
}

variable "enable_google_login" {
  type        = bool
  default     = true
  description = "Provision the Google LOGIN OAuth client secrets (Sign-in with Google). On by default to preserve existing behavior."
}

variable "enable_github_login" {
  type        = bool
  default     = false
  description = "Provision the GitHub LOGIN OAuth App secrets (Sign-in with GitHub). Off by default; enable per-env via tfvars."
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
  count     = var.enable_google_login ? 1 : 0
  secret_id = "${var.base_prefix}-oauth-client-id"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "oauth_client_id" {
  count       = var.enable_google_login ? 1 : 0
  secret      = google_secret_manager_secret.oauth_client_id[0].id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

resource "google_secret_manager_secret" "oauth_client_secret" {
  count     = var.enable_google_login ? 1 : 0
  secret_id = "${var.base_prefix}-oauth-client-secret"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "oauth_client_secret" {
  count       = var.enable_google_login ? 1 : 0
  secret      = google_secret_manager_secret.oauth_client_secret[0].id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

# Preserve existing dev/prod state (and the manually-populated secret values)
# now that the Google login resources are count-gated: un-indexed → [0].
moved {
  from = google_secret_manager_secret.oauth_client_id
  to   = google_secret_manager_secret.oauth_client_id[0]
}
moved {
  from = google_secret_manager_secret.oauth_client_secret
  to   = google_secret_manager_secret.oauth_client_secret[0]
}
moved {
  from = google_secret_manager_secret_version.oauth_client_id
  to   = google_secret_manager_secret_version.oauth_client_id[0]
}
moved {
  from = google_secret_manager_secret_version.oauth_client_secret
  to   = google_secret_manager_secret_version.oauth_client_secret[0]
}

# --- GitHub LOGIN OAuth App (Sign-in with GitHub, read:user/user:email).
#     Register an OAuth App (not a GitHub App) under the `overfolder` org, one
#     per environment. Feeds `GITHUB_AUTH_CLIENT_ID/_SECRET`. Gated on
#     `enable_github_login`; populate values manually post-apply via
#     `gcloud secrets versions add`. ---

resource "google_secret_manager_secret" "github_auth_client_id" {
  count     = var.enable_github_login ? 1 : 0
  secret_id = "${var.base_prefix}-github-auth-client-id"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "github_auth_client_id" {
  count       = var.enable_github_login ? 1 : 0
  secret      = google_secret_manager_secret.github_auth_client_id[0].id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

resource "google_secret_manager_secret" "github_auth_client_secret" {
  count     = var.enable_github_login ? 1 : 0
  secret_id = "${var.base_prefix}-github-auth-client-secret"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "github_auth_client_secret" {
  count       = var.enable_github_login ? 1 : 0
  secret      = google_secret_manager_secret.github_auth_client_secret[0].id
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

# --- oversla.sh shortener API key. Clients (overslash-api) and the shortener
#     service both read this secret. Value populated manually via
#     `gcloud secrets versions add` (random 32+ byte base64). ---

resource "google_secret_manager_secret" "shortener_api_key" {
  secret_id = "${var.base_prefix}-shortener-api-key"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "shortener_api_key" {
  secret      = google_secret_manager_secret.shortener_api_key.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

# --- overfwd gateway key. The shared Mailbox Gateway checks it as
#     `Authorization: Bearer`; the API injects it for every org through the
#     platform-credential rung, so no org has to store it. Both services read
#     this one secret, so rotating it is a single `versions add` followed by a
#     revision roll of each.
#
#     Generated here rather than left as REPLACE_ME: nothing outside this
#     deployment needs to know the value, so there is no reason for a human to
#     ever see it. `random_password` keeps it in state (like db_password), which
#     is already the case for every other generated credential here.

resource "google_secret_manager_secret" "overfwd_gateway_key" {
  secret_id = "${var.base_prefix}-overfwd-gateway-key"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "random_password" "overfwd_gateway_key" {
  length = 48
  # Alphanumeric only: the value travels as an HTTP bearer token and lands in
  # env vars on two services — punctuation buys no entropy worth the quoting
  # hazards.
  special = false
}

resource "google_secret_manager_secret_version" "overfwd_gateway_key" {
  secret      = google_secret_manager_secret.overfwd_gateway_key.id
  secret_data = random_password.overfwd_gateway_key.result

  # A rotation is `gcloud secrets versions add` out-of-band; terraform must not
  # drag the secret back to its generated value on the next apply.
  lifecycle {
    ignore_changes = [secret_data]
  }
}

# --- Stripe billing secrets (only populated when cloud_billing=true).
#     Values populated manually via `gcloud secrets versions add` after apply.

resource "google_secret_manager_secret" "stripe_secret_key" {
  secret_id = "${var.base_prefix}-stripe-secret-key"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "stripe_secret_key" {
  secret      = google_secret_manager_secret.stripe_secret_key.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

resource "google_secret_manager_secret" "stripe_webhook_secret" {
  secret_id = "${var.base_prefix}-stripe-webhook-secret"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "stripe_webhook_secret" {
  secret      = google_secret_manager_secret.stripe_webhook_secret.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

# --- PagerDuty integration key (only used when `pagerduty_enabled=true` on the
#     monitoring module). Populated manually via:
#       gcloud secrets versions add overslash-prod-pagerduty-integration-key \
#         --data-file=- < /path/to/integration-key

resource "google_secret_manager_secret" "pagerduty_integration_key" {
  secret_id = "${var.base_prefix}-pagerduty-integration-key"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "pagerduty_integration_key" {
  secret      = google_secret_manager_secret.pagerduty_integration_key.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

# --- Transactional-email provider API key (only consumed when
#     email_provider != "" on the cloud-run module). Populated manually via:
#       echo -n "re_…" | gcloud secrets versions add <base_prefix>-email-api-key --data-file=-

resource "google_secret_manager_secret" "email_api_key" {
  secret_id = "${var.base_prefix}-email-api-key"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "email_api_key" {
  secret      = google_secret_manager_secret.email_api_key.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

output "stripe_secret_key_secret_id" {
  value = google_secret_manager_secret.stripe_secret_key.secret_id
}

output "stripe_webhook_secret_secret_id" {
  value = google_secret_manager_secret.stripe_webhook_secret.secret_id
}

output "db_password_secret_id" {
  value = google_secret_manager_secret.db_password.secret_id
}

output "shortener_api_key_secret_id" {
  value = google_secret_manager_secret.shortener_api_key.secret_id
}

output "overfwd_gateway_key_secret_id" {
  value = google_secret_manager_secret.overfwd_gateway_key.secret_id
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
  value = var.enable_google_login ? google_secret_manager_secret.oauth_client_id[0].secret_id : ""
}

output "oauth_client_secret_secret_id" {
  value = var.enable_google_login ? google_secret_manager_secret.oauth_client_secret[0].secret_id : ""
}

output "github_auth_client_id_secret_id" {
  value = var.enable_github_login ? google_secret_manager_secret.github_auth_client_id[0].secret_id : ""
}

output "github_auth_client_secret_secret_id" {
  value = var.enable_github_login ? google_secret_manager_secret.github_auth_client_secret[0].secret_id : ""
}

output "google_services_client_id_secret_id" {
  value = google_secret_manager_secret.google_services_client_id.secret_id
}

output "google_services_client_secret_secret_id" {
  value = google_secret_manager_secret.google_services_client_secret.secret_id
}

output "pagerduty_integration_key_secret_id" {
  value = google_secret_manager_secret.pagerduty_integration_key.secret_id
}

output "email_api_key_secret_id" {
  value = google_secret_manager_secret.email_api_key.secret_id
}
