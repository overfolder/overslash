# overfwd — the shared Mailbox Gateway behind `services/email.yaml`.
#
# A stateless REST facade over IMAP/SMTP (https://github.com/overspiral/overfwd).
# It holds no credentials and no mail at rest: the mailbox login arrives on every
# request as `X-Mailbox-Auth`, is used, and is forgotten. One shared deployment
# therefore protects exactly as much as a per-org copy would, at a fraction of
# the cost and with one key to rotate instead of N.

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

variable "image" {
  type        = string
  description = "Fully-qualified overfwd image. Pin by digest — this is a third-party image we deploy but do not build, so a moving tag is an unreviewed code change in production."

  validation {
    condition     = length(var.image) > 0
    error_message = "image is required. Set `overfwd_image` in your tfvars (digest-pinned)."
  }
}

variable "cpu" {
  type        = string
  description = "Kept at 1: below one vCPU Cloud Run forces max concurrency to 1, which would serialize every mailbox call."
  default     = "1"
}

variable "memory" {
  type        = string
  description = "Measured footprint at rest is ~17MiB RSS. 256Mi is legal only because `cpu_idle = true` below throttles CPU between requests — Cloud Run rejects <512Mi on always-allocated CPU. The risk this must cover is concurrency, not the average: `get` buffers a whole message with attachments, which is why `concurrency` is capped low."
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

variable "concurrency" {
  type        = number
  description = "Requests in flight per instance. Far below Cloud Run's default 80 because each in-flight `get` can hold a full message (attachments included) in memory, and the limit is 256Mi: a handful of large fetches, not the average, is what would OOM an instance. Raise this and raise `memory` with it."
  default     = 8
}

variable "api_key_secret_id" {
  type        = string
  description = "GSM secret ID whose latest version is the gateway bearer token. The same secret feeds the API's platform-credential rung, so both sides rotate together."

  validation {
    condition     = length(var.api_key_secret_id) > 0
    error_message = "api_key_secret_id is required — the shared gateway must not run unauthenticated."
  }
}

variable "domain" {
  type        = string
  default     = ""
  description = "Hostname to expose via a Cloud Run domain mapping (e.g. `mailbox.overslash.com`). Requires a CNAME -> ghs.googlehosted.com and a verified apex. Empty leaves the service on its run.app URL."
}

variable "rust_log" {
  type    = string
  default = "info,overfwd=info"
}

locals {
  # Cloud Run v2 auto-injects PORT from `ports.container_port` and rejects an
  # explicit PORT env var; overfwd takes its bind address from OVERFWD_BIND
  # instead, so there is no clash.
  env_vars = {
    OVERFWD_BIND = "0.0.0.0:8000"
    # A shared gateway on the public internet must not be an open IMAP/SMTP
    # proxy. Callers authenticate with `Authorization: Bearer`; the key is
    # injected for every org by the API's platform-credential rung, so no org
    # has to hold it.
    OVERFWD_REQUIRE_API_KEY = "true"
    # A shared gateway takes its IMAP/SMTP endpoint from headers every tenant
    # can influence, and the autoconfig-derived path is the only one overfwd
    # address-checks by default — an explicit `X-Mailbox-Imap: host:port` is
    # dialled as given, deliberately, so a self-hosted GreenMail on
    # `localhost:3143` works. Multi-tenant that is an SSRF primitive, so this
    # deployment opts in: overfwd v0.3.0+ refuses a target that is (or resolves
    # to) a loopback/RFC1918/link-local/ULA address. Requires the pinned image
    # in `overfwd_image` or newer — on an older one the var is an unknown-key
    # no-op, not an error.
    OVERFWD_BLOCK_PRIVATE_ENDPOINTS = "true"
    # `POST /mcp` sits behind the same bearer gate as `/email/*`, so leaving it
    # on would add no unauthenticated surface — but the `email` template is an
    # HTTP-runtime service that only ever calls `/email/*`, so it is surface we
    # would ship without consuming. Off.
    OVERFWD_ENABLE_MCP = "false"
    RUST_LOG           = var.rust_log
  }

  env_secrets = {
    OVERFWD_API_KEY = var.api_key_secret_id
  }
}

resource "google_cloud_run_v2_service" "overfwd" {
  name     = "${var.base_prefix}-overfwd"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = var.service_account_email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    max_instance_request_concurrency = var.concurrency

    # Deliberately NO vpc_access block.
    #
    # Two reasons. (1) overfwd needs plain internet egress to IMAP 993 /
    # SMTP 465; a connector without a NAT path for those ports breaks it, and
    # Cloud Run's default direct egress reaches them fine. (2) Defense in depth
    # behind OVERFWD_BLOCK_PRIVATE_ENDPOINTS above: with no connector attached,
    # "internal" is the container itself and the GCP metadata endpoint —
    # nothing of ours — so even a bypass of the address check reaches nothing
    # worth reaching. Attaching a connector later would undo that; don't,
    # without re-reading D39.

    containers {
      image = var.image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        # Request-based billing: CPU throttled between requests. The gateway is
        # idle except while proxying, and this also lifts the always-allocated
        # 512Mi floor if the memory limit is ever lowered.
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

      # `GET /openapi.json` is the only unauthenticated route — overfwd ships
      # no /health, and every /email/* route 401s once require_api_key is on,
      # which a probe would read as a failing container.
      startup_probe {
        http_get {
          path = "/openapi.json"
          port = 8000
        }
        initial_delay_seconds = 2
        period_seconds        = 3
        failure_threshold     = 10
      }

      liveness_probe {
        http_get {
          path = "/openapi.json"
          port = 8000
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
}

# Public invoker: the gateway authenticates its own callers with a bearer token
# (OVERFWD_REQUIRE_API_KEY above), and orgs running their own overfwd reach a
# different deployment entirely. IAM-gating this would not help — the API calls
# it as an ordinary upstream HTTP service, not as an authenticated GCP client.
resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.overfwd.name
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
    route_name = google_cloud_run_v2_service.overfwd.name
  }
}

output "service_url" {
  value = google_cloud_run_v2_service.overfwd.uri
}

output "service_name" {
  value = google_cloud_run_v2_service.overfwd.name
}
