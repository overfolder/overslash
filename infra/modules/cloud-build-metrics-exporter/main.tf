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

locals {
  image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-metrics-exporter"

  # Distinct tag under the `/cache` path Kaniko used, so old blobs age out alone.
  cache_ref = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-metrics-exporter/cache:buildcache"
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
  # - Cargo.toml / Cargo.lock / rust-toolchain.toml: the workspace inputs
  #   cargo-chef distills into the dependency recipe.
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
    # AR token for the buildx step (see the cloud-build (API) module).
    step {
      name       = "gcr.io/google.com/cloudsdktool/cloud-sdk"
      entrypoint = "bash"
      args       = ["-c", "gcloud auth print-access-token > /workspace/.ar-token"]
    }

    # Registry layer cache: a fresh VM per build means it can't live on disk.
    # Replaces Kaniko (archived June 2025). See the cloud-build (API) module.
    step {
      name       = "gcr.io/cloud-builders/docker"
      entrypoint = "bash"
      args = ["-c", <<-EOT
        set -eu
        docker login -u oauth2accesstoken --password-stdin \
          https://${var.region}-docker.pkg.dev < /workspace/.ar-token
        rm -f /workspace/.ar-token
        docker buildx create --name cloudbuild --driver docker-container --use --bootstrap
        docker buildx build \
          --file crates/overslash-metrics-exporter/Dockerfile \
          --tag ${local.image}:$COMMIT_SHA \
          --tag ${local.image}:latest \
          --cache-from type=registry,ref=${local.cache_ref} \
          --cache-to type=registry,ref=${local.cache_ref},mode=max,image-manifest=true,oci-mediatypes=true \
          --provenance=false \
          --progress=plain \
          --push \
          .
      EOT
      ]
    }

    step {
      name       = "gcr.io/google.com/cloudsdktool/cloud-sdk"
      entrypoint = "gcloud"
      args = [
        "run", "jobs", "update", var.cloud_run_job_name,
        "--image", "${local.image}:$COMMIT_SHA",
        "--region", var.region,
      ]
    }

    options {
      logging      = "CLOUD_LOGGING_ONLY"
      machine_type = "E2_HIGHCPU_8"
    }

    # Cold builds recompile every dep and warm ones pay a cache export; 1200s was tight.
    timeout = "1800s"
  }
}

output "trigger_id" {
  value = google_cloudbuild_trigger.deploy.trigger_id
}
