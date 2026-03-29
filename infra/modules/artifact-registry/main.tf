variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "cloud_build_sa_email" {
  type = string
}

resource "google_artifact_registry_repository" "overslash" {
  location      = var.region
  repository_id = "overslash"
  description   = "Overslash Docker images"
  format        = "DOCKER"
  project       = var.project_id

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }
}

output "repository_id" {
  value = google_artifact_registry_repository.overslash.id
}

output "repository_name" {
  value = google_artifact_registry_repository.overslash.repository_id
}

output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.overslash.repository_id}"
}
