# Project-level guardrails (CASA 3.1.1, 6.2.1, 6.7.1; docs/compliance/casa/gcp-posture.md).
#
# Two halves:
#
# 1. The `roles/editor` grants GCP made at project creation, which Google's IAM
#    Recommender flagged and nothing else in this repo owns:
#      - the default Compute Engine SA: 0 permissions used in 90 days, and
#        nothing runs as it (every Cloud Run service/job, Cloud Build trigger
#        and Scheduler job names its own SA) -> removed.
#      - the Google APIs service agent (`@cloudservices`): the 12 permissions it
#        used are all the Serverless VPC Access connector's managed instance
#        group -> `roles/compute.editor`, only where that connector exists.
#    `google_project_iam_member_remove` keeps them removed: a binding re-added
#    out-of-band shows up as drift on the next plan and is removed again.
#
# 2. Organization policies set on the project, so the posture lives in this
#    repo rather than depending on what the parent org happens to inherit.
#    Org-wide policies belong to the org repo; these are the ones whose value
#    is Overslash-specific (per-env exceptions) or that pin a guarantee this
#    project relies on.
#
# Applying needs `roles/orgpolicy.policyAdmin` on the org, which Owner on the
# project does not carry. Runbook: docs/runbooks/project-guardrails.md.

variable "project_id" {
  type = string
}

variable "vpc_connector_enabled" {
  type        = bool
  description = "Whether a Serverless VPC Access connector exists (use_private_vpc). Its managed instance group is what the Google APIs service agent needs compute.editor for."
}

variable "restrict_sql_public_ip" {
  type        = bool
  description = "Enforce sql.managed.restrictPublicIp and sql.managed.restrictAuthorizedNetworks. False on dev, whose database has a public IP with no authorized networks."
}

variable "allow_service_account_key_creation" {
  type        = bool
  description = "Turn iam.managed.disableServiceAccountKeyCreation off for this project. The org enforces it; dev opts out so the Directory-sync key can be minted there."
}

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  compute_default_sa = "serviceAccount:${data.google_project.current.number}-compute@developer.gserviceaccount.com"
  cloudservices      = "serviceAccount:${data.google_project.current.number}@cloudservices.gserviceaccount.com"
}

# --- Default-SA Editor ---

resource "google_project_iam_member_remove" "compute_default_sa_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = local.compute_default_sa
}

# Granted before Editor is taken away, so the connector never loses the
# instance-group permissions mid-apply.
resource "google_project_iam_member" "cloudservices_compute_editor" {
  count = var.vpc_connector_enabled ? 1 : 0

  project = var.project_id
  role    = "roles/compute.editor"
  member  = local.cloudservices
}

resource "google_project_iam_member_remove" "cloudservices_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = local.cloudservices

  depends_on = [google_project_iam_member.cloudservices_compute_editor]
}

# --- Organization policies ---

# Default SAs are never created with Editor. Inherited from the org today;
# pinned here so it survives a change of parent.
resource "google_org_policy_policy" "automatic_iam_grants" {
  name   = "projects/${var.project_id}/policies/iam.automaticIamGrantsForDefaultServiceAccounts"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# ...and no one grants them Editor/Owner later. The constraint above only acts
# when a default SA is created; this one acts on every IAM policy write. Set
# after the removals so it never judges a policy that still holds the grants.
resource "google_org_policy_policy" "no_basic_roles_for_default_sas" {
  name   = "projects/${var.project_id}/policies/iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }

  depends_on = [
    google_project_iam_member_remove.compute_default_sa_editor,
    google_project_iam_member_remove.cloudservices_editor,
  ]
}

# The Data Access audit config (modules/audit-logging) cannot be quietly
# narrowed by exempting a principal.
resource "google_org_policy_policy" "no_audit_logging_exemption" {
  name   = "projects/${var.project_id}/policies/iam.disableAuditLoggingExemption"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# No bucket can be made public. Every bucket here is already `enforced`.
resource "google_org_policy_policy" "storage_public_access_prevention" {
  name   = "projects/${var.project_id}/policies/storage.publicAccessPrevention"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# Set explicitly in both directions, so an org-level change cannot flip
# either environment.
resource "google_org_policy_policy" "sql_restrict_public_ip" {
  name   = "projects/${var.project_id}/policies/sql.managed.restrictPublicIp"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = var.restrict_sql_public_ip ? "TRUE" : "FALSE"
    }
  }
}

resource "google_org_policy_policy" "sql_restrict_authorized_networks" {
  name   = "projects/${var.project_id}/policies/sql.managed.restrictAuthorizedNetworks"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = var.restrict_sql_public_ip ? "TRUE" : "FALSE"
    }
  }
}

# The dev override already exists (set by hand on 2026-10-27); the runbook
# imports it before the first apply.
resource "google_org_policy_policy" "service_account_key_creation" {
  name   = "projects/${var.project_id}/policies/iam.managed.disableServiceAccountKeyCreation"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = var.allow_service_account_key_creation ? "FALSE" : "TRUE"
    }
  }
}
