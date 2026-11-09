# A platform-hosted, multi-tenant MCP gateway: the shared WhatsApp or Telegram
# server behind `services/whatsapp.yaml` / `services/telegram.yaml`
# (docs/design/hosted-runtimes.md, Phase 0).
#
# The overfwd module with the parts that differ for a stateful MCP server:
#
# - One deployment serves every org. The gateway key (`key_env`) is the outer
#   key, injected by the API's platform-credential rung and pinned to `domain`.
#   The per-instance session token rides in `Authorization: Bearer` and picks
#   the tenant.
# - The container keeps no durable state. Sessions live in the runtime's own
#   store (Postgres, object storage), configured through `env` and
#   `env_secrets`. Cloud Run may replace an instance at any time.
# - A paired session has to stay connected to receive messages, so CPU is
#   always allocated, and by default exactly one instance runs. Two instances
#   would both connect the same session until the runtime leases sessions
#   between replicas. Raise `max_instances` only for a runtime that does.

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "name" {
  type        = string
  description = "Hosted runtime key (`whatsapp`, `telegram`). Names the service `<base_prefix>-<name>-gateway`."
}

variable "service_account_email" {
  type        = string
  description = "The gateway's own identity. It has no project roles, and reads only the secrets in `key_secret_id` and `env_secrets`."
}

variable "image" {
  type        = string
  description = "Fully-qualified image, pinned by digest."

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be digest-pinned (…@sha256:<64 hex chars>)."
  }
}

variable "port" {
  type    = number
  default = 8080
}

variable "probe_path" {
  type        = string
  description = "Unauthenticated liveness/startup path."
  default     = "/healthz"
}

variable "key_env" {
  type        = string
  description = "Env var the runtime reads its gateway key from."
  default     = "GATEWAY_KEY"
}

variable "key_secret_id" {
  type        = string
  description = "GSM secret ID of the gateway key. The API reads the same secret for its platform-credential rung, so both sides rotate together."

  validation {
    condition     = length(var.key_secret_id) > 0
    error_message = "key_secret_id is required — a shared gateway must not run unauthenticated."
  }
}

variable "env" {
  type        = map(string)
  default     = {}
  description = "Extra plain env vars (non-secret runtime config)."
}

variable "env_secrets" {
  type        = map(string)
  default     = {}
  description = "Extra env vars from Secret Manager, env name → secret ID (e.g. the runtime's session-store DSN). Each is granted to this service account alone."
}

variable "cpu" {
  type    = string
  default = "1"
}

variable "memory" {
  type        = string
  description = "Always-allocated CPU requires at least 512Mi on Cloud Run."
  default     = "512Mi"
}

variable "min_instances" {
  type        = number
  description = "Kept at 1: paired sessions must stay connected to receive messages, so the gateway never scales to zero."
  default     = 1
}

variable "max_instances" {
  type        = number
  description = "Kept at 1 until the runtime leases each session to one replica; two replicas would both connect the same session."
  default     = 1
}

variable "concurrency" {
  type    = number
  default = 40
}

variable "domain" {
  type        = string
  description = "Hostname for the Cloud Run domain mapping (e.g. `whatsapp-mcp.overslash.com`). Required: the API pins the platform key to this host. Needs a CNAME -> ghs.googlehosted.com and a verified apex."

  validation {
    condition     = length(var.domain) > 0
    error_message = "domain is required: the platform credential is pinned to it."
  }
}

locals {
  env_secrets = merge({ (var.key_env) = var.key_secret_id }, var.env_secrets)
}

# One grant per secret (CASA 6.7.1, docs/compliance/casa/secrets-access-policy.md).
resource "google_secret_manager_secret_iam_member" "env_secrets" {
  for_each = local.env_secrets

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_email}"
}

resource "google_cloud_run_v2_service" "gateway" {
  name                 = "${var.base_prefix}-${var.name}-gateway"
  location             = var.region
  project              = var.project_id
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = true

  template {
    service_account = var.service_account_email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    max_instance_request_concurrency = var.concurrency

    # Deliberately NO vpc_access block, for the same reason as overfwd (D39):
    # the runtime needs plain internet egress to WhatsApp/Telegram, and with no
    # connector attached a compromised runtime reaches nothing of ours. A
    # session store it needs (Cloud SQL, GCS) is reached over its public,
    # IAM- or password-authenticated endpoint, never through our VPC.

    containers {
      image = var.image

      ports {
        container_port = var.port
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        # Always-allocated CPU: a paired session keeps a live connection open
        # between requests, and throttling CPU while idle would stall it.
        cpu_idle          = false
        startup_cpu_boost = true
      }

      dynamic "env" {
        for_each = var.env
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
          path = var.probe_path
          port = var.port
        }
        initial_delay_seconds = 2
        period_seconds        = 3
        failure_threshold     = 20
      }

      liveness_probe {
        http_get {
          path = var.probe_path
          port = var.port
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

  depends_on = [google_secret_manager_secret_iam_member.env_secrets]
}

resource "google_cloud_run_domain_mapping" "domain" {
  location = var.region
  name     = var.domain
  project  = var.project_id

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.gateway.name
  }
}

output "service_url" {
  value = google_cloud_run_v2_service.gateway.uri
}

output "service_name" {
  value = google_cloud_run_v2_service.gateway.name
}
