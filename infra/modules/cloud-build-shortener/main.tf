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

variable "cloud_run_service" {
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
  image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/oversla-sh"

  # Distinct tag under the `/cache` path Kaniko used, so old blobs age out alone.
  cache_ref = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/oversla-sh/cache:buildcache"
}

resource "google_cloudbuild_trigger" "deploy" {
  name     = "${var.base_prefix}-shortener-deploy"
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

  # Only rebuild when something that actually affects the shortener
  # image changes. Prevents every master push (dashboard, docs, other
  # crates) from firing a shortener build + deploy — which would waste
  # Cloud Build minutes and churn Cloud Run revisions with identical
  # images tagged by new commit SHAs.
  included_files = [
    "crates/oversla-sh/**",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
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
          --file crates/oversla-sh/Dockerfile \
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
        "run", "deploy", var.cloud_run_service,
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
