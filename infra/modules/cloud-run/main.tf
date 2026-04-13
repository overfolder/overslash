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

variable "signing_key_secret_id" {
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

variable "dashboard_origin" {
  type    = string
  default = "*localhost*"
}

variable "dashboard_url" {
  type    = string
  default = "/"
}

variable "enable_dev_auth" {
  type    = bool
  default = false
}

variable "redis_host" {
  type    = string
  default = ""
}

variable "redis_port" {
  type    = string
  default = ""
}

locals {
  env_vars = merge(
    {
      APPROVAL_EXPIRY_SECS      = "1800"
      CLOUD_SQL_CONNECTION_NAME = var.cloud_sql_connection_name
      DASHBOARD_ORIGIN          = var.dashboard_origin
      DASHBOARD_URL             = var.dashboard_url
      DB_NAME                   = var.db_name
      DB_USER                   = var.db_user
      HOST                      = "0.0.0.0"
      RUST_LOG                  = "info"
      SERVICES_DIR              = "/app/services"
    },
    var.dashboard_url != "/" ? { PUBLIC_URL = var.dashboard_url } : {},
    var.enable_dev_auth ? { DEV_AUTH = "1" } : {},
    var.redis_host != "" ? { REDIS_URL = "redis://${var.redis_host}:${var.redis_port}" } : {},
  )

  env_secrets = {
    DB_PASSWORD               = var.db_password_secret_id
    GOOGLE_AUTH_CLIENT_ID     = var.oauth_client_id_secret_id
    GOOGLE_AUTH_CLIENT_SECRET = var.oauth_client_secret_secret_id
    SECRETS_ENCRYPTION_KEY    = var.encryption_key_secret_id
    SIGNING_KEY               = var.signing_key_secret_id
  }
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

      dynamic "env" {
        for_each = local.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.env_secrets
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
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
