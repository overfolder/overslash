variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "service_account_email" {
  type = string
}

variable "use_private_vpc" {
  type    = bool
  default = false
}

variable "vpc_connector_id" {
  type    = string
  default = ""
}

variable "image" {
  type = string
}

variable "cpu" {
  type    = string
  default = "1"
}

variable "memory" {
  type    = string
  default = "256Mi"
}

variable "min_instances" {
  type    = number
  default = 0
}

variable "max_instances" {
  type    = number
  default = 3
}

variable "cloud_sql_connection_name" {
  type = string
}

variable "db_password_secret_id" {
  type = string
}

variable "encryption_key_secret_id" {
  type = string
}

variable "oauth_client_id_secret_id" {
  type = string
}

variable "oauth_client_secret_secret_id" {
  type = string
}

variable "db_user" {
  type = string
}

variable "db_name" {
  type = string
}

variable "domain" {
  type    = string
  default = ""
}

variable "redis_host" {
  type    = string
  default = ""
}

variable "redis_port" {
  type    = string
  default = ""
}

resource "google_cloud_run_v2_service" "api" {
  name     = "${var.base_prefix}-api"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = var.service_account_email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    # VPC access only when using private networking
    dynamic "vpc_access" {
      for_each = var.use_private_vpc ? [1] : []
      content {
        connector = var.vpc_connector_id
        egress    = "PRIVATE_RANGES_ONLY"
      }
    }

    # Cloud SQL Auth Proxy (works for both public and private IP modes)
    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [var.cloud_sql_connection_name]
      }
    }

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        startup_cpu_boost = true
      }

      env {
        name  = "HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "RUST_LOG"
        value = "info"
      }
      env {
        name  = "APPROVAL_EXPIRY_SECS"
        value = "1800"
      }
      dynamic "env" {
        for_each = var.domain != "" ? [1] : []
        content {
          name  = "PUBLIC_URL"
          value = "https://${var.domain}"
        }
      }
      env {
        name  = "SERVICES_DIR"
        value = "/app/services"
      }
      env {
        name  = "DB_USER"
        value = var.db_user
      }
      env {
        name  = "DB_NAME"
        value = var.db_name
      }
      env {
        name  = "CLOUD_SQL_CONNECTION_NAME"
        value = var.cloud_sql_connection_name
      }

      env {
        name = "DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = var.db_password_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "SECRETS_ENCRYPTION_KEY"
        value_source {
          secret_key_ref {
            secret  = var.encryption_key_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "GOOGLE_AUTH_CLIENT_ID"
        value_source {
          secret_key_ref {
            secret  = var.oauth_client_id_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "GOOGLE_AUTH_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = var.oauth_client_secret_secret_id
            version = "latest"
          }
        }
      }

      dynamic "env" {
        for_each = var.redis_host != "" ? [1] : []
        content {
          name  = "REDIS_URL"
          value = "redis://${var.redis_host}:${var.redis_port}"
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 10
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        period_seconds    = 30
        failure_threshold = 3
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
    ]
  }
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_domain_mapping" "domain" {
  count    = var.domain != "" ? 1 : 0
  location = var.region
  name     = var.domain
  project  = var.project_id

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.api.name
  }
}

output "service_url" {
  value = google_cloud_run_v2_service.api.uri
}

output "service_name" {
  value = google_cloud_run_v2_service.api.name
}
