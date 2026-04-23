# Isolated Cloud Run service that hosts third-party MCP server subprocesses.
# Copy-reduced from `cloud-run` with three deliberate differences:
#
#   1. No Cloud SQL Auth Proxy volume/mount — the runtime never touches the
#      database; the api decrypts secrets and sends plaintext env on each
#      /invoke.
#   2. No Secret Manager env bindings — the runtime's own SA doesn't have
#      `roles/secretmanager.secretAccessor`. Secrets reach the runtime
#      only in the body of `/invoke` requests from the api.
#   3. `ingress = INTERNAL`, and invoker is bound to the api's SA, not
#      `allUsers`. The runtime must not be reachable from the internet;
#      only the api talks to it.
#
# This module intentionally does NOT manage the SA, Artifact Registry, or
# Cloud Build — those are either pre-existing or added to the top-level
# `main.tf` alongside the existing api plumbing.

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
  description = "Dedicated SA for the runtime. Must have no Secret Manager / Cloud SQL roles."
  type        = string
}

variable "image" {
  description = "Fully-qualified image, e.g. $${region}-docker.pkg.dev/$${project}/$${repo}/overslash-mcp-runtime:$${sha}"
  type        = string
}

variable "api_service_account_email" {
  description = "api's SA — granted roles/run.invoker on this service."
  type        = string
}

variable "shared_secret_secret_id" {
  description = "Secret Manager secret holding MCP_RUNTIME_SHARED_SECRET. Mounted into the container."
  type        = string
}

variable "cpu" {
  type    = string
  default = "2"
}

# MCP subprocesses live inside this container. Sized so the default pool
# (~40 paused + 5 active × ~80MB = ~3.5GB) fits with headroom. Operators
# override via the enclosing env's tfvars if a specific MCP is memory-hungry.
variable "memory" {
  type    = string
  default = "4Gi"
}

# min_instances=1 so the runtime stays warm and can pause-not-restart
# long-lived MCP subprocesses. Set to 0 in tfvars for idle cost savings
# (pays a ~1s cold start + subprocess respawn on the first call).
variable "min_instances" {
  type    = number
  default = 1
}

variable "max_instances" {
  type    = number
  default = 3
}

variable "idle_pause_ms" {
  description = "MCP subprocess SIGSTOP threshold. Matches the runtime's IDLE_PAUSE_MS env."
  type        = number
  default     = 300000
}

variable "idle_shutdown_ms" {
  description = "MCP subprocess kill threshold. Matches the runtime's IDLE_SHUTDOWN_MS env."
  type        = number
  default     = 1800000
}

variable "default_limit_memory_mb" {
  description = "Default prlimit --as cap per MCP subprocess (MB)."
  type        = number
  default     = 4096
}

variable "default_limit_cpu_seconds" {
  description = "Default prlimit --cpu cap per MCP subprocess (seconds)."
  type        = number
  default     = 300
}

resource "google_cloud_run_v2_service" "runtime" {
  name     = "${var.base_prefix}-mcp-runtime"
  location = var.region
  project  = var.project_id
  # INTERNAL: reachable only via the project's VPC or other Cloud Run
  # services in the same project. Combined with the SA-gated invoker
  # binding below, this is the primary isolation boundary between the
  # api and the untrusted MCP subprocess layer.
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = var.service_account_email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
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
        name  = "PORT"
        value = "8080"
      }
      env {
        name  = "LOG_LEVEL"
        value = "info"
      }
      env {
        name  = "REQUIRE_PRLIMIT"
        value = "true"
      }
      env {
        name  = "IDLE_PAUSE_MS"
        value = tostring(var.idle_pause_ms)
      }
      env {
        name  = "IDLE_SHUTDOWN_MS"
        value = tostring(var.idle_shutdown_ms)
      }
      env {
        name  = "DEFAULT_LIMIT_MEMORY_MB"
        value = tostring(var.default_limit_memory_mb)
      }
      env {
        name  = "DEFAULT_LIMIT_CPU_SECONDS"
        value = tostring(var.default_limit_cpu_seconds)
      }

      env {
        name = "MCP_RUNTIME_SHARED_SECRET"
        value_source {
          secret_key_ref {
            secret  = var.shared_secret_secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        initial_delay_seconds = 3
        period_seconds        = 3
        failure_threshold     = 10
      }

      liveness_probe {
        http_get {
          path = "/healthz"
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

# Only the api's SA may invoke the runtime. No `allUsers`, no public URL.
resource "google_cloud_run_v2_service_iam_member" "api_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.runtime.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.api_service_account_email}"
}

output "service_url" {
  value = google_cloud_run_v2_service.runtime.uri
}

output "service_name" {
  value = google_cloud_run_v2_service.runtime.name
}
