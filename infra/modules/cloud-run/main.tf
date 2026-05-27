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
  type        = string
  default     = ""
  description = "Apex API hostname to expose via a Cloud Run domain mapping (e.g. `api.dev.overslash.com`). Empty disables the apex mapping. Used in the no-LB path; when fronted by `module.api_lb`, leave this empty so the LB owns the cert/route."
}

variable "extra_api_domain_mappings" {
  type        = list(string)
  default     = []
  description = "Additional fully-qualified hostnames to expose via 1-1 `google_cloud_run_domain_mapping` resources. Used in the no-LB dev path to map a small set of per-org subdomains (e.g. `[\"acme.api.dev.overslash.com\"]`) without provisioning a global LB + wildcard cert. Each entry must already have a CNAME -> ghs.googlehosted.com (or A record to Cloud Run's regional IPs) and the dashboard operator must have verified the apex via Search Console."
}

variable "app_host_suffix" {
  type        = string
  default     = ""
  description = "Apex for the dashboard subdomain surface, e.g. `app.overslash.com`. Empty disables wildcard routing on this surface."
}

variable "api_host_suffix" {
  type        = string
  default     = ""
  description = "Apex for the programmatic (MCP / OAuth-AS / REST) subdomain surface, e.g. `api.overslash.com`. Empty disables wildcard routing on this surface."
}

variable "session_cookie_domain" {
  type        = string
  default     = ""
  description = "Domain attribute for the session cookie (typically `.app.overslash.com` so subdomains share the cookie). Empty leaves cookies origin-scoped."
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

variable "overslash_env" {
  type        = string
  default     = ""
  description = "Deployment env marker (e.g. dev/prod) propagated as OVERSLASH_ENV. Used as the env half of the Vercel preview OAuth handoff defense-in-depth gate."
}

variable "vercel_preview_origin_regex" {
  type        = string
  default     = ""
  description = "Regex matching Vercel preview-deployment URLs allowed to OAuth-handoff back to themselves (dev only). Empty = feature off; production must leave empty."
}

variable "connection_return_url_hosts" {
  type        = string
  default     = ""
  description = "Comma-separated hostnames allowed as OAuth return_url redirect targets. Empty = feature disabled (Overslash falls back to JSON)."
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

variable "email_provider" {
  type        = string
  default     = ""
  description = "Transactional-email provider key. Currently only `resend` is recognised; empty (the default) keeps the API on the NoopMailer fallback. Setting this requires email_from + the email_api_key secret to be populated, otherwise the API refuses to boot."
}

variable "email_from" {
  type        = string
  default     = ""
  description = "From address used on every outbound transactional email (e.g. `no-reply@mail.overslash.com`). Must be a domain the configured provider is authorised to send for. Required when email_provider != \"\"."
}

variable "email_reply_to" {
  type        = string
  default     = ""
  description = "Optional Reply-To address. Empty leaves the provider's default (usually From)."
}

variable "email_api_key_secret_id" {
  type        = string
  default     = ""
  description = "GSM secret ID holding the provider API key (Resend `re_…`). Only consumed when email_provider != \"\"."
}

variable "rust_log" {
  type        = string
  default     = "info"
  description = "RUST_LOG value passed to the API container. Override per-env (e.g. `debug` for dev)."
}

variable "enable_metrics_sidecar" {
  type        = bool
  default     = true
  description = "Run an OTel collector sidecar that scrapes /internal/metrics and ships to Google Managed Prometheus. Required for the Prometheus-backed dashboards and alerts."
}

variable "read_oauth_credentials_from_env" {
  type        = bool
  default     = false
  description = "Set OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1, enabling the tier-4 env-var fallback in the OAuth credential cascade (OAUTH_GOOGLE_* picked up from Cloud Run env). Safe in dev; must be false in prod."
}

variable "enable_shortener_client" {
  type        = bool
  default     = false
  description = "Inject OVERSLA_SH_BASE_URL + OVERSLA_SH_API_KEY so the API can mint short links via the oversla.sh service."
}

variable "oversla_sh_base_url" {
  type        = string
  default     = ""
  description = "Public base URL of the oversla.sh shortener (e.g. https://oversla.sh). Only used when enable_shortener_client=true."
}

variable "shortener_api_key_secret_id" {
  type        = string
  default     = ""
  description = "GSM secret ID holding the shortener API key. Only consumed when enable_shortener_client=true."
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
      LOG_FORMAT   = "json"
      RUST_LOG     = var.rust_log
      SERVICES_DIR = "/app/services"
    },
    var.dashboard_url != "/" ? { PUBLIC_URL = var.dashboard_url } : {},
    var.enable_dev_auth ? { DEV_AUTH = "1" } : {},
    var.redis_host != "" ? { REDIS_URL = "redis://${var.redis_host}:${var.redis_port}" } : {},
    var.cloud_billing ? {
      CLOUD_BILLING         = "true"
      STRIPE_EUR_LOOKUP_KEY = var.stripe_eur_lookup_key
      STRIPE_USD_LOOKUP_KEY = var.stripe_usd_lookup_key
    } : {},
    var.email_provider != "" ? merge(
      {
        EMAIL_PROVIDER = var.email_provider
        EMAIL_FROM     = var.email_from
      },
      var.email_reply_to != "" ? { EMAIL_REPLY_TO = var.email_reply_to } : {},
    ) : {},
    var.app_host_suffix != "" ? { APP_HOST_SUFFIX = var.app_host_suffix } : {},
    var.api_host_suffix != "" ? { API_HOST_SUFFIX = var.api_host_suffix } : {},
    var.session_cookie_domain != "" ? { SESSION_COOKIE_DOMAIN = var.session_cookie_domain } : {},
    var.overslash_env != "" ? { OVERSLASH_ENV = var.overslash_env } : {},
    var.vercel_preview_origin_regex != "" ? { PREVIEW_ORIGIN_ALLOWLIST = var.vercel_preview_origin_regex } : {},
    var.connection_return_url_hosts != "" ? { OVERSLASH_CONNECTION_RETURN_URL_HOSTS = var.connection_return_url_hosts } : {},
    var.read_oauth_credentials_from_env ? { OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS = "1" } : {},
    var.enable_shortener_client && var.oversla_sh_base_url != "" ? { OVERSLA_SH_BASE_URL = var.oversla_sh_base_url } : {},
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
    var.email_provider != "" && var.email_api_key_secret_id != "" ? {
      EMAIL_API_KEY = var.email_api_key_secret_id
    } : {},
    var.enable_shortener_client && var.shortener_api_key_secret_id != "" ? {
      OVERSLA_SH_API_KEY = var.shortener_api_key_secret_id
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
          startup_cpu_boost = true
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
      client,
      client_version,
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

# 1-1 domain mappings for per-org API subdomains in the no-LB dev path.
# When the global API LB is enabled (`module.api_lb`), leave
# `extra_api_domain_mappings = []` so requests flow through the LB +
# wildcard cert. When disabled, each entry here gets its own DNS-validated
# Cloud Run domain mapping. Cloud Run's per-project mapping cap is the
# practical ceiling here — keep the list short.
resource "google_cloud_run_domain_mapping" "extra" {
  for_each = toset(var.extra_api_domain_mappings)
  location = var.region
  name     = each.value
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
