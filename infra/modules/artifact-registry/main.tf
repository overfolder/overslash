variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

# Age after which artifact versions (deployed images AND Kaniko cache
# layers) become eligible for deletion. MUST stay above the Kaniko
# --cache-ttl (currently 168h/7d) set in the cloud-build modules: any cache
# layer Kaniko would reuse is re-pushed within the TTL, so it is always
# younger than this threshold and never pruned. Default 30 days.
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

resource "google_artifact_registry_repository" "repo" {
  location      = var.region
  repository_id = "${var.base_prefix}-registry"
  description   = "${var.base_prefix} Docker images"
  format        = "DOCKER"
  project       = var.project_id

  cleanup_policy_dry_run = var.cleanup_dry_run

  # Protect the 10 most recent versions of every package (images and the
  # Kaniko cache) from deletion regardless of age. Safety net for rollbacks
  # and always keeps the live :latest / newest-SHA images. KEEP takes
  # precedence over the DELETE policy below on any overlap.
  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  # Delete versions older than the threshold to bound repo growth. Without a
  # DELETE policy a KEEP-only config deletes nothing, so the registry (and
  # the Kaniko cache) grows unbounded. Covers both images and cache layers;
  # see cleanup_delete_older_than for why the age must exceed the Kaniko
  # cache TTL. The keep-recent policy above still protects the 10 newest
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

output "repository_id" {
  value = google_artifact_registry_repository.repo.id
}

output "repository_name" {
  value = google_artifact_registry_repository.repo.repository_id
}

output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}"
}
