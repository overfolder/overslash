variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "memory_size_gb" {
  type    = number
  default = 1
}

variable "authorized_network" {
  type = string
}

resource "google_redis_instance" "valkey" {
  name           = "${var.base_prefix}-valkey"
  project        = var.project_id
  region         = var.region
  tier           = "BASIC"
  memory_size_gb = var.memory_size_gb
  redis_version  = "REDIS_7_2"

  authorized_network = var.authorized_network

  # CASA 6.7.1. The cache holds resolver output (names, addresses, phone
  # numbers) and session-revocation state, so being on the VPC is not enough:
  # every client presents the AUTH string and talks TLS, verifying the server
  # against the instance's own CA. With TLS on, the endpoint moves to 6378.
  #
  # `transit_encryption_mode` can only be set when an instance is created, so
  # flipping it on an existing instance REPLACES it: new IP, empty keyspace,
  # minutes of downtime. See docs/runbooks/memorystore-auth-tls.md before
  # applying.
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  display_name = "${var.base_prefix} Valkey"
}

# The AUTH string and server CA reach Cloud Run through Secret Manager
# (`secret_key_ref`), never as plaintext env. The Cloud Run SA already holds
# project-level `secretAccessor` (modules/iam). Both values also sit in
# Terraform state, as every provider-generated credential here does.
resource "google_secret_manager_secret" "auth_string" {
  secret_id = "${var.base_prefix}-valkey-auth"
  project   = var.project_id
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "auth_string" {
  secret      = google_secret_manager_secret.auth_string.id
  secret_data = google_redis_instance.valkey.auth_string
}

resource "google_secret_manager_secret" "server_ca" {
  secret_id = "${var.base_prefix}-valkey-server-ca"
  project   = var.project_id
  replication {
    auto {}
  }
}

# Every CA the instance currently serves, concatenated. During a CA rotation
# Memorystore lists the old and new CA side by side; re-applying picks the new
# one up, and clients trust both until the old one expires.
resource "google_secret_manager_secret_version" "server_ca" {
  secret      = google_secret_manager_secret.server_ca.id
  secret_data = join("", google_redis_instance.valkey.server_ca_certs[*].cert)
}

output "redis_host" {
  value = google_redis_instance.valkey.host
}

output "redis_port" {
  value = tostring(google_redis_instance.valkey.port)
}

# Read through the *version* resources so a Cloud Run revision that
# references them is never created before a version exists to resolve.
output "auth_secret_id" {
  value = element(split("/", google_secret_manager_secret_version.auth_string.secret), 3)
}

output "server_ca_secret_id" {
  value = element(split("/", google_secret_manager_secret_version.server_ca.secret), 3)
}
