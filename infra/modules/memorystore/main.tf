variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "instance_name" {
  type        = string
  description = "Memorystore instance ID. Changing it builds a new instance next to the old one (create_before_destroy) and repoints Cloud Run before the old one goes."
}

variable "engine_version" {
  type    = string
  default = "VALKEY_9_1"
}

variable "node_type" {
  type    = string
  default = "SHARED_CORE_NANO"
}

variable "network_id" {
  type = string
}

variable "subnet_id" {
  type        = string
  description = "Subnet the PSC endpoints take their IPs from."
}

variable "client_service_accounts" {
  type        = map(string)
  description = "Service accounts the clients connect as, keyed by a stable name (`api`, `shortener`). Each is granted roles/memorystore.dbConnectionUser on this instance only."
}

# Memorystore for Valkey is reached over Private Service Connect, not VPC
# peering. The policy lets Memorystore create the PSC endpoints in our VPC.
# One policy per network, region and service class, so it is named after the
# environment, not the instance, and survives an instance rename.
resource "google_network_connectivity_service_connection_policy" "memorystore" {
  name          = "${var.base_prefix}-memorystore"
  project       = var.project_id
  location      = var.region
  service_class = "gcp-memorystore"
  network       = var.network_id
  psc_config {
    subnetworks = [var.subnet_id]
  }
}

resource "google_memorystore_instance" "cache" {
  instance_id = var.instance_name
  project     = var.project_id
  location    = var.region

  mode           = "CLUSTER_DISABLED"
  shard_count    = 1
  replica_count  = 0
  node_type      = var.node_type
  engine_version = var.engine_version

  # CASA 6.7.1. The cache holds resolver output (names, addresses, phone
  # numbers) and session-revocation state, so being on the VPC is not enough:
  # every client authenticates and talks TLS, verifying the server against the
  # instance's own CA. Valkey has no static AUTH string; clients present a
  # short-lived access token for their service account instead (IAM_AUTH).
  # Both settings are immutable: changing either replaces the instance.
  authorization_mode      = "IAM_AUTH"
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  desired_auto_created_endpoints {
    network    = var.network_id
    project_id = var.project_id
  }

  deletion_protection_enabled = false

  depends_on = [google_network_connectivity_service_connection_policy.memorystore]

  # A rename (instance_name) builds the new instance first, so Cloud Run moves
  # over in the same apply and the old instance is only deleted afterwards.
  lifecycle {
    create_before_destroy = true
  }
}

# Scoped to this instance, so a stray instance in the project is not reachable
# with the same identity. Replaced before destroy on a rename, so the old
# instance keeps accepting the clients still pointed at it.
resource "google_project_iam_member" "client" {
  for_each = var.client_service_accounts

  project = var.project_id
  role    = "roles/memorystore.dbConnectionUser"
  member  = "serviceAccount:${each.value}"

  condition {
    title      = "${var.instance_name} only"
    expression = "resource.name == \"${google_memorystore_instance.cache.id}\""
  }

  lifecycle {
    create_before_destroy = true
  }
}

# The API's binding predates the map. Without this, the plan would create the
# keyed copy and then delete the old address, and deleting an IAM member with
# the same role, member and condition removes the grant both addresses share.
moved {
  from = google_project_iam_member.client
  to   = google_project_iam_member.client["api"]
}

locals {
  connections = flatten([for e in google_memorystore_instance.cache.endpoints : e.connections])
  primary = one([
    for c in flatten([for c in local.connections : c.psc_auto_connection]) : c
    if c.connection_type == "CONNECTION_TYPE_PRIMARY"
  ])
}

# The server CA reaches Cloud Run through Secret Manager (`secret_key_ref`),
# like every other mounted value. The secret is named after the instance, so a
# rename writes a fresh secret instead of colliding with the old instance's.
# The API reads it under its `<base_prefix>-*` secret rule (modules/secret-
# manager), so `instance_name` must keep that prefix; the shortener is granted
# it by name in modules/cloud-run-shortener.
resource "google_secret_manager_secret" "server_ca" {
  secret_id = "${var.instance_name}-server-ca"
  project   = var.project_id
  replication {
    auto {}
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Every CA chain the instance currently serves, concatenated. During a CA
# rotation Memorystore lists the old and new side by side; re-applying picks
# the new one up, and clients trust both until the old one expires.
resource "google_secret_manager_secret_version" "server_ca" {
  secret = google_secret_manager_secret.server_ca.id
  secret_data = join("", flatten([
    for ca in google_memorystore_instance.cache.managed_server_ca : [
      for chain in ca.ca_certs : chain.certificates
    ]
  ]))

  lifecycle {
    create_before_destroy = true
  }
}

# The outputs wait on the IAM binding, so a Cloud Run revision that reads
# them is never rolled out before its identity is allowed to connect. Without
# this, a rename (one apply) could boot revisions that fail AUTH and stay on
# their in-memory fallbacks until they restart.
output "host" {
  value      = local.primary.ip_address
  depends_on = [google_project_iam_member.client]
}

output "port" {
  value      = tostring(local.primary.port)
  depends_on = [google_project_iam_member.client]
}

# Read through the *version* resource so a Cloud Run revision that references
# it is never created before a version exists to resolve.
output "server_ca_secret_id" {
  value      = element(split("/", google_secret_manager_secret_version.server_ca.secret), 3)
  depends_on = [google_project_iam_member.client]
}
