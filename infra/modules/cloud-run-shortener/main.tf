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

variable "vpc_connector_id" {
  type        = string
  description = "Serverless VPC Access connector ID. Required — the shortener has to reach private Memorystore."

  validation {
    condition     = length(var.vpc_connector_id) > 0
    error_message = "vpc_connector_id is required. The shortener must reach private Memorystore via a Serverless VPC Access connector. Set `use_private_vpc = true` so module.networking produces a connector."
  }
}

variable "image" {
  type = string
}

variable "cpu" {
  type    = string
  default = "1"
}

variable "memory" {
  type        = string
  description = "Cloud Run memory. 256Mi is fine because `cpu_idle = true` below puts us on request-based billing (CPU only allocated during requests), which lifts the 512Mi floor."
  default     = "256Mi"
}

variable "min_instances" {
  type    = number
  default = 0
}

variable "max_instances" {
  type    = number
  default = 3
}

variable "api_key_secret_id" {
  type        = string
  description = "GSM secret ID whose latest version is the shortener API key."
}

variable "valkey_host" {
  type = string

  validation {
    condition     = length(var.valkey_host) > 0
    error_message = "valkey_host is required. Set `enable_valkey = true` and `use_private_vpc = true` so module.memorystore is provisioned."
  }
}

variable "valkey_port" {
  type = string

  validation {
    condition     = length(var.valkey_port) > 0
    error_message = "valkey_port is required (same precondition as valkey_host)."
  }
}

variable "base_url" {
  type        = string
  description = "Public URL used in the short_url response (e.g. https://oversla.sh)."

  validation {
    condition     = length(var.base_url) > 0
    error_message = "base_url is required. Set `shortener_base_url` (e.g. \"https://oversla.sh\") in your tfvars."
  }
}

variable "root_redirect_url" {
  type        = string
  description = "Where `GET /` 302s to. Empty string = 404 on root."
  default     = ""
}

variable "domain" {
  type    = string
  default = ""
}

variable "min_ttl_secs" {
  type    = number
  default = 60
}

variable "max_ttl_secs" {
  type    = number
  default = 604800
}

locals {
  # Cloud Run v2 auto-injects PORT from `ports.container_port` below and
  # rejects an explicit PORT env var. Don't set it here.
  env_vars = merge(
    {
      HOST         = "0.0.0.0"
      VALKEY_URL   = "redis://${var.valkey_host}:${var.valkey_port}"
      BASE_URL     = var.base_url
      MIN_TTL_SECS = tostring(var.min_ttl_secs)
      MAX_TTL_SECS = tostring(var.max_ttl_secs)
      RUST_LOG     = "info,oversla_sh=info"
    },
    var.root_redirect_url != "" ? { ROOT_REDIRECT_URL = var.root_redirect_url } : {},
  )

  env_secrets = {
    API_KEY = var.api_key_secret_id
  }
}

resource "google_cloud_run_v2_service" "shortener" {
  name     = "${var.base_prefix}-shortener"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = var.service_account_email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    # Mandatory: private VPC access for Memorystore reachability.
    vpc_access {
      connector = var.vpc_connector_id
      egress    = "PRIVATE_RANGES_ONLY"
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
        # Request-based billing: CPU throttled when idle. Fits a shortener
        # whose only work is a Valkey GET per request; also lifts the
        # always-allocated 512Mi memory floor so 256Mi is legal.
        cpu_idle          = true
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

      startup_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        initial_delay_seconds = 2
        period_seconds        = 3
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
  name     = google_cloud_run_v2_service.shortener.name
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
    route_name = google_cloud_run_v2_service.shortener.name
  }
}

output "service_url" {
  value = google_cloud_run_v2_service.shortener.uri
}

output "service_name" {
  value = google_cloud_run_v2_service.shortener.name
}
