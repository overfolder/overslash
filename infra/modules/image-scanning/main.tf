# Read-only identity for the scheduled container image check (CASA 6.1.1;
# docs/runbooks/image-scanning.md). The scanning itself needs no resource here:
# containerscanning.googleapis.com (infra/main.tf) turns it on for the project.
#
# .github/workflows/image-scan.yml signs in through Workload Identity Federation
# because the org bans service account keys. It can read what is deployed and
# what the scanner found, and nothing else.

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "github_owner" {
  type = string
}

variable "github_repo" {
  type = string
}

# Numeric ids, because a deleted org or repo name can be registered by someone
# else and a name match would then still pass.
variable "github_owner_id" {
  type    = string
  default = "262421904"
}

variable "github_repository_id" {
  type    = string
  default = "1189468982"
}

# The repositories holding deployed images. Reading a tag resolves it to the
# digest the scanner keys its results on.
variable "repository_names" {
  type = list(string)
}

locals {
  workflow = "${var.github_owner}/${var.github_repo}/.github/workflows/image-scan.yml"
}

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "Federated identity for GitHub Actions workflows"
}

resource "google_iam_workload_identity_pool_provider" "image_scan" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "image-scan"
  display_name                       = "Image scan workflow"
  description                        = "image-scan.yml on dev and master"

  # One workflow file, on the two protected branches. Scheduled runs use the
  # default branch; `dev` is there for a manual run. A PR's token carries a
  # refs/pull ref and is refused, so a PR cannot read through this identity.
  attribute_condition = <<-EOT
    assertion.repository_owner_id == "${var.github_owner_id}" &&
    assertion.repository_id == "${var.github_repository_id}" &&
    assertion.workflow_ref in [
      "${local.workflow}@refs/heads/dev",
      "${local.workflow}@refs/heads/master"
    ]
  EOT

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "image_scan" {
  project      = var.project_id
  account_id   = "${var.base_prefix}-imgscan"
  display_name = "${var.base_prefix} container image check"
}

resource "google_service_account_iam_member" "github_impersonation" {
  service_account_id = google_service_account.image_scan.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_owner}/${var.github_repo}"
}

# Lists Cloud Run services and jobs, to find the images actually deployed. This
# includes plain env values; secrets are Secret Manager references, not values.
resource "google_project_iam_member" "run_viewer" {
  project = var.project_id
  role    = "roles/run.viewer"
  member  = "serviceAccount:${google_service_account.image_scan.email}"
}

resource "google_project_iam_member" "occurrences_viewer" {
  project = var.project_id
  role    = "roles/containeranalysis.occurrences.viewer"
  member  = "serviceAccount:${google_service_account.image_scan.email}"
}

resource "google_artifact_registry_repository_iam_member" "reader" {
  for_each = toset(var.repository_names)

  project    = var.project_id
  location   = var.region
  repository = each.value
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.image_scan.email}"
}

output "workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.image_scan.name
}

output "service_account_email" {
  value = google_service_account.image_scan.email
}
