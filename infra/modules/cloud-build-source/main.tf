# The `<project>_cloudbuild` bucket. Cloud Build creates it on the first
# `gcloud builds submit` and stages the uploaded source archive there, with
# legacy ACLs and public-access prevention merely inherited. None of our
# triggers use it — they are GitHub-connected and clone from GitHub — but
# deleting it would only let the next manual submit recreate it with the same
# defaults. Owning it keeps the name taken and hardened (CASA, gcp-posture.md).
# Adopted by the `import` block in infra/main.tf; see
# docs/runbooks/cloud-build-bucket.md.

variable "project_id" {
  type = string
}

resource "google_storage_bucket" "source" {
  name    = "${var.project_id}_cloudbuild"
  project = var.project_id

  # Must match the auto-created bucket (gcloud's default): changing either
  # forces a replacement, not an in-place update.
  location      = "US"
  storage_class = "STANDARD"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  # Only a manual `gcloud builds submit` writes here; a month is enough to
  # debug one. Also clears the bootstrap-era archive on first apply.
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}

output "name" {
  value = google_storage_bucket.source.name
}
