variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "region" {
  type        = string
  description = "Region the audit log bucket lives in."
}

variable "base_prefix" {
  type        = string
  description = "Prefix used for resource names (e.g. overslash-dev)."
}

variable "retention_days" {
  type        = number
  default     = 400
  description = "Retention of the audit log bucket. 400 days matches GCP's own `_Required` bucket and covers a full CASA revalidation cycle (12 months) plus five weeks of slack. On a LOCKED bucket this can never be changed again — not raised, not lowered."

  validation {
    condition     = var.retention_days >= 365 && var.retention_days <= 3650
    error_message = "retention_days must be between 365 (the 6.7.1 floor we committed to) and 3650 (the Cloud Logging maximum)."
  }
}

variable "locked" {
  type        = bool
  default     = false
  description = "IRREVERSIBLE. Lock the audit bucket's retention policy. Once applied, the retention period can never be changed, the bucket cannot be deleted until every entry in it has aged out, and the lock itself cannot be removed — not by Terraform, not by a project Owner, not by Google support."
}

variable "audited_services" {
  type        = list(string)
  default     = ["secretmanager.googleapis.com", "cloudsql.googleapis.com", "run.googleapis.com"]
  description = "Services whose Data Access audit logs (ADMIN_READ, DATA_READ, DATA_WRITE) are turned on. Admin Activity logs are always on and need no config. Use the service name the audit logs are emitted under (protoPayload.serviceName): Cloud SQL logs as cloudsql.googleapis.com, not its API endpoint sqladmin.googleapis.com."
}

variable "expected_secret_accessors" {
  type        = list(string)
  description = "Principal emails whose AccessSecretVersion calls are the normal runtime path and do not alert. Service accounts only — humans reading through Terraform are exempted by terraform_operators instead, and nowhere else. See docs/compliance/casa/secrets-access-policy.md."

  validation {
    condition     = length(var.expected_secret_accessors) > 0 && alltrue([for p in var.expected_secret_accessors : endswith(p, ".gserviceaccount.com")])
    error_message = "expected_secret_accessors must be a non-empty list of service-account emails. Human principals belong in terraform_operators, which exempts only their Terraform reads."
  }
}

variable "terraform_operators" {
  type        = list(string)
  default     = []
  description = "Principal emails (humans or service accounts) whose secret reads through the google Terraform provider do not alert — the reads every `tofu plan`/`apply` makes. Their reads by any other client (Console, gcloud, db-shell) still alert. See docs/compliance/casa/secrets-access-policy.md."
}

variable "alerts_enabled" {
  type        = bool
  default     = false
  description = "Create the unexpected-secret-access alert policy. Mirrors the monitoring module's gate (alert_email != \"\"). The log-based metric is created either way."
}

variable "notification_channels" {
  type        = list(string)
  default     = []
  description = "Notification channel IDs for the unexpected-secret-access alert."
}
