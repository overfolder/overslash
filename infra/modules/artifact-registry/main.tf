variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

# Age after which artifact versions (deployed images AND the BuildKit layer
# cache the cloud-build modules export) become eligible for deletion. Each
# build re-pushes the `:buildcache` manifest, so the live cache version is
# always newer than this threshold; what ages out is the superseded,
# now-untagged versions behind it. Default 30 days.
variable "cleanup_delete_older_than" {
  type    = string
  default = "2592000s" # 30 days
}

# When true, cleanup policies are evaluated and logged but nothing is
# deleted. Flip on to verify the deletion scope before enforcing.
variable "cleanup_dry_run" {
  type    = bool
  default = false
}

# Provision a pull-through cache of Docker Hub. Needed for third-party images
# we deploy but do not build (overfwd, the OTel sidecar), so Cloud Run pulls from Artifact
# Registry rather than depending on Docker Hub's availability and rate limits
# at revision-deploy time. Digest pins stay valid: a remote repository serves
# the upstream manifest unchanged.
variable "enable_docker_hub_remote" {
  type    = bool
  default = false
}

resource "google_artifact_registry_repository" "repo" {
  location      = var.region
  repository_id = "${var.base_prefix}-registry"
  description   = "${var.base_prefix} Docker images"
  format        = "DOCKER"
  project       = var.project_id

  cleanup_policy_dry_run = var.cleanup_dry_run

  # Follow the project's Container Scanning API. Pinned so that turning a repo
  # off by hand shows up as drift (CASA 6.1.1; docs/runbooks/image-scanning.md).
  vulnerability_scanning_config {
    enablement_config = "INHERITED"
  }

  # Protect the 10 most recent versions of every package from deletion
  # regardless of age. Safety net for rollbacks, and always keeps the live
  # :latest / newest-SHA images. KEEP takes precedence over the DELETE policy
  # below on any overlap.
  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  # Delete versions older than the threshold to bound repo growth. Without a
  # DELETE policy a KEEP-only config deletes nothing, so the registry grows
  # unbounded. The keep-recent policy above still protects the 10 newest
  # versions per package even if they are older than this.
  cleanup_policies {
    id     = "delete-old"
    action = "DELETE"

    condition {
      older_than = var.cleanup_delete_older_than
      tag_state  = "ANY"
    }
  }
}

# BuildKit layer cache, kept apart from the images because scanning is set per
# repository. `image-manifest=true` stores each export as an ordinary OCI image,
# so Container Scanning scans and bills it like one, though nothing runs it
# (docs/runbooks/image-scanning.md). Stays out of `repository_names`: the
# scheduled check reads deployed images only.
resource "google_artifact_registry_repository" "build_cache" {
  location      = var.region
  repository_id = "${var.base_prefix}-buildcache"
  description   = "${var.base_prefix} BuildKit layer cache (not deployed, not scanned)"
  format        = "DOCKER"
  project       = var.project_id

  cleanup_policy_dry_run = var.cleanup_dry_run

  vulnerability_scanning_config {
    enablement_config = "DISABLED"
  }

  # Keeps the current cache manifest alive through a quiet month with no builds.
  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  # Every build adds a version, so without this the cache grows unbounded.
  cleanup_policies {
    id     = "delete-old"
    action = "DELETE"

    condition {
      older_than = var.cleanup_delete_older_than
      tag_state  = "ANY"
    }
  }
}

# Pull-through cache of Docker Hub. Carries no cleanup policies: its contents
# are cached upstream layers, not artifacts we own, and Artifact Registry
# manages their lifetime itself.
resource "google_artifact_registry_repository" "docker_hub" {
  count = var.enable_docker_hub_remote ? 1 : 0

  location      = var.region
  repository_id = "${var.base_prefix}-dockerhub"
  description   = "Remote (pull-through) mirror of Docker Hub"
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  project       = var.project_id

  # overfwd and the OTel sidecar deploy from here, so they must be scanned too.
  vulnerability_scanning_config {
    enablement_config = "INHERITED"
  }

  remote_repository_config {
    description = "Docker Hub"
    docker_repository {
      public_repository = "DOCKER_HUB"
    }
  }
}

output "repository_id" {
  value = google_artifact_registry_repository.repo.id
}

output "repository_name" {
  value = google_artifact_registry_repository.repo.repository_id
}

# Every repository in this module, for grants that cover all deployed images.
output "repository_names" {
  value = concat(
    [google_artifact_registry_repository.repo.repository_id],
    google_artifact_registry_repository.docker_hub[*].repository_id,
  )
}

output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}"
}

output "build_cache_repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.build_cache.repository_id}"
}

# Base for Docker Hub images pulled through the mirror: append the upstream
# path, e.g. `<url>/angelmanuel/overfwd@sha256:…`. Empty when the mirror is off.
output "docker_hub_repository_url" {
  value = var.enable_docker_hub_remote ? "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.docker_hub[0].repository_id}" : ""
}
