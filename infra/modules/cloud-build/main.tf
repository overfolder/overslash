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
    # Build with Kaniko so the Docker layer cache persists across builds.
    # Cloud Build runs each build on a fresh VM, so a plain `docker build`
    # always starts from a cold cache and recompiles every Rust dependency
    # from scratch (~6 min), wasting the dependency-caching layer the
    # Dockerfile is carefully designed around. Kaniko stores each layer
    # (including the builder-stage dependency layer) as a content-addressed
    # blob in a dedicated cache repo (<dest>/cache), keyed by command+input
    # hash, so unchanged layers are reused. It also pushes the image
    # directly, replacing the separate `docker push` step. The cache repo
    # lives in the same Artifact Registry repository and is isolated per
    # project (dev vs prod), so it needs no extra IAM; --cache-ttl bounds
    # staleness to one week.
    step {
      name = "gcr.io/kaniko-project/executor:latest"
      args = [
        "--dockerfile=crates/overslash-api/Dockerfile",
        "--context=dir:///workspace",
        "--destination=${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-api:$COMMIT_SHA",
        "--destination=${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-api:latest",
        "--cache=true",
        # Pin the cache repo explicitly. Kaniko otherwise infers it from a
        # --destination; the tagged ($COMMIT_SHA) destinations make that
        # inference fragile, so we point every build at one stable repo.
        "--cache-repo=${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-api/cache",
        "--cache-ttl=168h",
      ]
    }

    step {
      name       = "gcr.io/google.com/cloudsdktool/cloud-sdk"
      entrypoint = "gcloud"
      args = [
        "run", "deploy", var.cloud_run_service,
        "--image", "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_name}/overslash-api:$COMMIT_SHA",
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
