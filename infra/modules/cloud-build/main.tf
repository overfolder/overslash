variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "env" {
  description = "Environment name (dev/prod). Gates the release-version build-arg."
  type        = string
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
  image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-api"

  # Distinct tag under the `/cache` path Kaniko used, so old blobs age out alone.
  cache_ref = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-api/cache:buildcache"

  # Only prod claims the clean manifest version. A branch-push deploy has no
  # release tag to inject, so OVERSLASH_RELEASE tells build.rs to drop the
  # "-dev" suffix from the manifest version; dev omits it and stays "-dev".
  release_build_arg = var.env == "prod" ? "--build-arg OVERSLASH_RELEASE=1" : ""
}

resource "google_cloudbuild_trigger" "deploy" {
  name     = "${var.base_prefix}-deploy"
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

  build {
    # buildx hands auth to a separate BuildKit container, so Cloud Build's own
    # docker credential wiring isn't enough — log in explicitly. /workspace is
    # the only volume shared between steps; the next step deletes the token.
    step {
      name       = "gcr.io/google.com/cloudsdktool/cloud-sdk"
      entrypoint = "bash"
      args       = ["-c", "gcloud auth print-access-token > /workspace/.ar-token"]
    }

    # Cloud Build gives each build a fresh VM, so the layer cache has to live in
    # the registry: mode=max exports every stage, incl. cargo-chef's dependency
    # layer. Replaces Kaniko (archived June 2025, OOM'd snapshotting that layer).
    # --provenance=false keeps the push a plain manifest, as Kaniko produced. D54.
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
          --file crates/overslash-api/Dockerfile \
          --build-arg OVERSLASH_GIT_SHA=$COMMIT_SHA \
          ${local.release_build_arg} \
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
      logging = "CLOUD_LOGGING_ONLY"
      # E2_HIGHCPU_32 is blocked by the "Default pool E2 CPU" quota, which Google won't raise.
      machine_type = "E2_HIGHCPU_8"
    }

    # Headroom for a cold build: libpg_query (D42) on top of ~6 min of Rust deps
    # crowds 1200s whenever the cargo-chef layer misses. Warm builds: minutes.
    timeout = "2400s"
  }
}

output "trigger_id" {
  value = google_cloudbuild_trigger.deploy.trigger_id
}
