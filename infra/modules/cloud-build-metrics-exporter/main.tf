# Build trigger for the metrics-exporter image. Same shape as the API
# Cloud Build module — push on the main deploy branch, build the exporter
# Dockerfile, push to Artifact Registry, then update the Cloud Run Job to
# the new image so the next scheduler tick picks it up.

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "repository_name" {
  type = string
}

variable "cloud_build_sa_id" {
  type = string
}

variable "cloud_run_job_name" {
  type = string
}

variable "github_owner" {
  type = string
}

variable "github_repo" {
  type = string
}

variable "github_branch" {
  type = string
}

resource "google_cloudbuild_trigger" "deploy" {
  name     = "${var.base_prefix}-metrics-exporter-deploy"
  project  = var.project_id
  location = var.region

  service_account = var.cloud_build_sa_id

  github {
    owner = var.github_owner
    name  = var.github_repo

    push {
      branch = var.github_branch
    }
  }

  # Path filter: only fire when something that actually goes into the
  # exporter image changes. Mirrors the shortener trigger's pattern.
  # - Cargo.toml / Cargo.lock / rust-toolchain.toml: workspace inputs the
  #   Dockerfile COPYs at the top of the builder stage.
  # - crates/overslash-metrics-exporter/**: the exporter sources + Dockerfile.
  # - .sqlx/**: offline sqlx query metadata used by SQLX_OFFLINE=true.
  # Sibling workspace crates (overslash-metrics, overslash-db, ...) are
  # intentionally excluded: the exporter has no path deps on them, so
  # their source changes don't affect the binary; any dep-graph impact
  # flows through Cargo.lock.
  included_files = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates/overslash-metrics-exporter/**",
    ".sqlx/**",
  ]

  build {
    # Build with Kaniko for persistent layer caching. Cloud Build uses a
    # fresh VM per run, so a plain `docker build` always hits a cold cache
    # and recompiles all Rust deps. Kaniko caches each layer (incl. the
    # builder-stage dependency layer) as content-addressed blobs in
    # <dest>/cache, isolated per project, and pushes the image directly
    # (replacing the separate push step). No extra IAM; --cache-ttl bounds
    # staleness. See the cloud-build (API) module for the full rationale.
    step {
      name = "gcr.io/kaniko-project/executor:latest"
      args = [
        "--dockerfile=crates/overslash-metrics-exporter/Dockerfile",
        "--context=dir:///workspace",
        "--destination=${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-metrics-exporter:$COMMIT_SHA",
        "--destination=${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-metrics-exporter:latest",
        "--cache=true",
        "--cache-ttl=168h",
      ]
    }

    step {
      name       = "gcr.io/google.com/cloudsdktool/cloud-sdk"
      entrypoint = "gcloud"
      args = [
        "run", "jobs", "update", var.cloud_run_job_name,
        "--image", "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-metrics-exporter:$COMMIT_SHA",
        "--region", var.region,
      ]
    }

    options {
      logging      = "CLOUD_LOGGING_ONLY"
      machine_type = "E2_HIGHCPU_8"
    }

    timeout = "1200s"
  }
}

output "trigger_id" {
  value = google_cloudbuild_trigger.deploy.trigger_id
}
