terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.7"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 8.7"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state in GCS. The bucket is managed out-of-band (see
  # `bin/bootstrap-tfstate.sh`) so it's not a chicken-and-egg for the
  # very state that lives in it. Versioning is enabled on the bucket
  # so `tofu state rm` / corruption is recoverable. Workspaces get
  # their own object path under `infra/terraform.tfstate`.
  backend "gcs" {
    bucket = "overslash-tfstate"
    prefix = "infra"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region

  # Bill API quota to the managed project instead of the ADC client's
  # project. Org Policy (project-guardrails) rejects user ADC calls
  # without a quota project.
  user_project_override = true
  billing_project       = var.project_id
}

provider "google-beta" {
  project = var.project_id
  region  = var.region

  # Bill API quota to the managed project instead of the ADC client's
  # project. Org Policy (project-guardrails) rejects user ADC calls
  # without a quota project.
  user_project_override = true
  billing_project       = var.project_id
}
