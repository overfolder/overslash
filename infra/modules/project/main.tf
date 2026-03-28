locals {
  name_prefix = "overslash-${var.environment}"
}

# ============================================================
# Artifact Registry
# ============================================================

resource "google_artifact_registry_repository" "overslash" {
  location      = var.region
  repository_id = "overslash"
  format        = "DOCKER"
  description   = "Overslash Docker images"
}

# ============================================================
# Networking
# ============================================================

resource "google_compute_network" "vpc" {
  name                    = "${local.name_prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${local.name_prefix}-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
}

# Private IP range for Cloud SQL peering
resource "google_compute_global_address" "private_ip_range" {
  name          = "${local.name_prefix}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "private_vpc" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]
}

# ============================================================
# Cloud SQL (PostgreSQL 16)
# ============================================================

resource "google_sql_database_instance" "postgres" {
  name             = "${local.name_prefix}-db"
  database_version = "POSTGRES_16"
  region           = var.region

  depends_on = [google_service_networking_connection.private_vpc]

  settings {
    tier            = var.cloud_sql_tier
    disk_size       = var.cloud_sql_disk_size_gb
    disk_autoresize = true
    availability_type = var.environment == "prod" ? "REGIONAL" : "ZONAL"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }

    backup_configuration {
      enabled                        = var.environment == "prod"
      point_in_time_recovery_enabled = var.environment == "prod"
    }

    database_flags {
      name  = "max_connections"
      value = "100"
    }
  }

  deletion_protection = var.environment == "prod"
}

resource "google_sql_database" "overslash" {
  name     = "overslash"
  instance = google_sql_database_instance.postgres.name
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_user" "overslash" {
  name     = "overslash"
  instance = google_sql_database_instance.postgres.name
  password = random_password.db_password.result
}

# ============================================================
# Secrets
# ============================================================

resource "google_secret_manager_secret" "database_url" {
  secret_id = "${local.name_prefix}-database-url"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "database_url" {
  secret      = google_secret_manager_secret.database_url.id
  secret_data = "postgres://overslash:${random_password.db_password.result}@${google_sql_database_instance.postgres.private_ip_address}:5432/overslash"
}

resource "google_secret_manager_secret" "encryption_key" {
  secret_id = "${local.name_prefix}-encryption-key"
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

# ============================================================
# IAM
# ============================================================

resource "google_service_account" "cloud_run" {
  account_id   = "${local.name_prefix}-run"
  display_name = "Overslash ${var.environment} Cloud Run"
}

resource "google_secret_manager_secret_iam_member" "run_database_url" {
  secret_id = google_secret_manager_secret.database_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_secret_manager_secret_iam_member" "run_encryption_key" {
  secret_id = google_secret_manager_secret.encryption_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# ============================================================
# Cloud Run
# ============================================================

resource "google_cloud_run_v2_service" "overslash" {
  name     = local.name_prefix
  location = var.region

  depends_on = [
    google_secret_manager_secret_version.database_url,
    google_secret_manager_secret_version.encryption_key,
  ]

  template {
    service_account = google_service_account.cloud_run.email

    scaling {
      min_instance_count = var.cloud_run_min_instances
      max_instance_count = var.cloud_run_max_instances
    }

    # Direct VPC egress for Cloud SQL private IP access
    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.name
        subnetwork = google_compute_subnetwork.subnet.name
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.docker_image

      ports {
        container_port = 3000
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      # Secrets injected from Secret Manager
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "SECRETS_ENCRYPTION_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.encryption_key.secret_id
            version = "latest"
          }
        }
      }

      # Plain environment variables
      env {
        name  = "HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "PORT"
        value = "3000"
      }
      env {
        name  = "RUST_LOG"
        value = var.environment == "prod" ? "info" : "debug"
      }
      env {
        name  = "SERVICES_DIR"
        value = "services"
      }
      env {
        name  = "PUBLIC_URL"
        value = var.domain != "" ? "https://${var.domain}" : ""
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 10
      }

      liveness_probe {
        http_get {
          path = "/health"
        }
        period_seconds = 15
      }
    }
  }
}

# Allow unauthenticated access (public API)
resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.overslash.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ============================================================
# Custom domain (optional)
# ============================================================

resource "google_cloud_run_domain_mapping" "custom" {
  count    = var.domain != "" ? 1 : 0
  name     = var.domain
  location = var.region

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.overslash.name
  }
}
