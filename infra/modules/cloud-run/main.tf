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
  type        = string
  description = "GSM secret ID for the Google LOGIN OAuth client (Sign-in with Google). Feeds GOOGLE_AUTH_CLIENT_ID."
}

variable "oauth_client_secret_secret_id" {
  type        = string
  description = "GSM secret ID for the Google LOGIN OAuth client secret. Feeds GOOGLE_AUTH_CLIENT_SECRET."
}

variable "google_services_client_id_secret_id" {
  type        = string
  description = "GSM secret ID for the Google SERVICES OAuth client (Calendar/Drive/Gmail). Feeds OAUTH_GOOGLE_CLIENT_ID."
}

variable "google_services_client_secret_secret_id" {
  type        = string
  description = "GSM secret ID for the Google SERVICES OAuth client secret. Feeds OAUTH_GOOGLE_CLIENT_SECRET."
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

variable "mcp_extra_origins" {
  type        = string
  default     = ""
  description = "Comma-separated origins allowed only on /mcp + /.well-known/oauth-* + /oauth/* (additional to dashboard_origin)."
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

variable "cloud_billing" {
  type    = bool
  default = false
}

variable "stripe_eur_lookup_key" {
  type    = string
  default = "overslash_seat_eur"
}

variable "stripe_usd_lookup_key" {
  type    = string
  default = "overslash_seat_usd"
}

variable "stripe_secret_key_secret_id" {
  type        = string
  default     = ""
  description = "GSM secret ID for the Stripe secret key. Only used when cloud_billing=true."
}

variable "stripe_webhook_secret_secret_id" {
  type        = string
  default     = ""
  description = "GSM secret ID for the Stripe webhook signing secret. Only used when cloud_billing=true."
}

variable "enable_metrics_sidecar" {
  type        = bool
  default     = true
  description = "Run an OTel collector sidecar that scrapes /internal/metrics and ships to Google Managed Prometheus. Required for the Prometheus-backed dashboards and alerts."
}

variable "metrics_sidecar_image" {
  type        = string
  default     = "otel/opentelemetry-collector-contrib:0.120.0"
  description = "OTel collector image. Pinned to a specific tag to avoid silent breakage on `:latest`."
}

variable "container_port" {
  type        = number
  default     = 8080
  description = "Port the API container listens on. The OTel sidecar scrapes localhost:<this>/internal/metrics."
}

locals {
  env_vars = merge(
    {
      APPROVAL_EXPIRY_SECS      = "1800"
      CLOUD_SQL_CONNECTION_NAME = var.cloud_sql_connection_name
      DASHBOARD_ORIGIN          = var.dashboard_origin
      MCP_EXTRA_ORIGINS         = var.mcp_extra_origins
      DASHBOARD_URL             = var.dashboard_url
      DB_NAME                   = var.db_name
      DB_USER                   = var.db_user
      HOST                      = "0.0.0.0"
      # Structured JSON logs so `make logs` can surface message/span fields
      # via `jsonPayload.*` instead of falling back to ANSI-coded textPayload.
      LOG_FORMAT = "json"
      # Enables tier-4 env-var fallback in the services OAuth cascade so the
      # overslash-managed default Google services client (OAUTH_GOOGLE_*) is
      # picked up when an org hasn't set its own credentials. Org-level BYO
      # via POST /v1/org/oauth-credentials/google still takes precedence.
      OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS = "1"
      RUST_LOG                                       = "info"
      SERVICES_DIR                                   = "/app/services"
    },
    var.dashboard_url != "/" ? { PUBLIC_URL = var.dashboard_url } : {},
    var.enable_dev_auth ? { DEV_AUTH = "1" } : {},
    var.redis_host != "" ? { REDIS_URL = "redis://${var.redis_host}:${var.redis_port}" } : {},
    var.cloud_billing ? {
      CLOUD_BILLING         = "true"
      STRIPE_EUR_LOOKUP_KEY = var.stripe_eur_lookup_key
      STRIPE_USD_LOOKUP_KEY = var.stripe_usd_lookup_key
    } : {},
  )

  env_secrets = merge(
    {
      DB_PASSWORD                = var.db_password_secret_id
      GOOGLE_AUTH_CLIENT_ID      = var.oauth_client_id_secret_id
      GOOGLE_AUTH_CLIENT_SECRET  = var.oauth_client_secret_secret_id
      OAUTH_GOOGLE_CLIENT_ID     = var.google_services_client_id_secret_id
      OAUTH_GOOGLE_CLIENT_SECRET = var.google_services_client_secret_secret_id
      SECRETS_ENCRYPTION_KEY     = var.encryption_key_secret_id
      SIGNING_KEY                = var.signing_key_secret_id
    },
    var.cloud_billing && var.stripe_secret_key_secret_id != "" ? {
      STRIPE_SECRET_KEY     = var.stripe_secret_key_secret_id
      STRIPE_WEBHOOK_SECRET = var.stripe_webhook_secret_secret_id
    } : {},
  )
}

# OTel collector config — generated from a template, stored in Secret Manager,
# mounted as a file in the sidecar container. Only created when the sidecar is
# enabled; otherwise nothing in this module touches Secret Manager.
resource "google_secret_manager_secret" "otel_config" {
  count     = var.enable_metrics_sidecar ? 1 : 0
  project   = var.project_id
  secret_id = "${var.base_prefix}-otel-collector-config"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "otel_config" {
  count  = var.enable_metrics_sidecar ? 1 : 0
  secret = google_secret_manager_secret.otel_config[0].id

  secret_data = templatefile("${path.module}/otel-collector-config.yaml.tftpl", {
    project_id = var.project_id
    region     = var.region
  })
}

resource "google_secret_manager_secret_iam_member" "otel_config_accessor" {
  count     = var.enable_metrics_sidecar ? 1 : 0
  project   = var.project_id
  secret_id = google_secret_manager_secret.otel_config[0].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_email}"
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

    # OTel sidecar config — mounted into the sidecar at /etc/otelcol.
    dynamic "volumes" {
      for_each = var.enable_metrics_sidecar ? [1] : []
      content {
        name = "otel-config"
        secret {
          secret = google_secret_manager_secret.otel_config[0].secret_id
          items {
            version = "latest"
            path    = "config.yaml"
          }
        }
      }
    }

    # Cloud SQL Auth Proxy (works for both public and private IP modes)
    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [var.cloud_sql_connection_name]
      }
    }

    # API container. Wrapped in a `dynamic` (always one element) so it lives
    # in the same kind of block as the optional OTel sidecar below. Mixing a
    # static `containers` block with a dynamic one would put both into the
    # same list but in an order Terraform's docs don't guarantee — and the
    # `lifecycle.ignore_changes` rule below references `containers[0]` by
    # index. With both blocks dynamic, source order is the merge order, so
    # the API container is unambiguously at index 0.
    dynamic "containers" {
      for_each = [1]
      content {
        name  = "api"
        image = var.image

        ports {
          container_port = var.container_port
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
            port = var.container_port
          }
          initial_delay_seconds = 5
          period_seconds        = 5
          failure_threshold     = 10
        }

        liveness_probe {
          http_get {
            path = "/health"
            port = var.container_port
          }
          period_seconds    = 30
          failure_threshold = 3
        }
      }
    }

    # OTel collector sidecar — scrapes /internal/metrics on loopback and
    # exports to Google Managed Prometheus. `depends_on` keeps Cloud Run from
    # marking the revision ready before the API container is up, which would
    # otherwise produce flaky scrape errors during cold starts.
    dynamic "containers" {
      for_each = var.enable_metrics_sidecar ? [1] : []
      content {
        name       = "otel-collector"
        image      = var.metrics_sidecar_image
        args       = ["--config=/etc/otelcol/config.yaml"]
        depends_on = ["api"]

        env {
          name  = "METRICS_PORT"
          value = tostring(var.container_port)
        }

        resources {
          limits = {
            cpu    = "250m"
            memory = "128Mi"
          }
        }

        volume_mounts {
          name       = "otel-config"
          mount_path = "/etc/otelcol"
        }
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
