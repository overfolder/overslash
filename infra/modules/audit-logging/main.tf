# Audit logging for CASA 6.7.1: record who reads server-side secrets, keep that
# record somewhere tamper-evident for a year, and notify when anyone other than
# the runtime reads one. Policy: docs/compliance/casa/secrets-access-policy.md.
#
# Four pieces:
#
# 1. Data Access audit logs on Secret Manager, Cloud SQL and Cloud Run.
#    GCP leaves these off by default, and the live projects returned
#    `auditConfigs: NONE` (gcp-posture.md), so an AccessSecretVersion on the
#    vault master key left no record at all.
# 2. A dedicated log bucket with >= 1 year retention, optionally LOCKED.
# 3. A sink routing every Cloud Audit Log in the project into that bucket. The
#    `_Default` sink keeps its own 30-day copy; this is the retained one.
# 4. A log-based metric counting AccessSecretVersion by any principal outside
#    `expected_secret_accessors`, and an alert on it.

# --- 1. Data Access audit logs ---
#
# Keyed by the service name the logs are emitted under. For Cloud SQL that is
# `cloudsql.googleapis.com`, NOT its API endpoint `sqladmin.googleapis.com`:
# every Cloud SQL audit entry in the live projects carries the former, and
# `sqladmin` in auditConfigs enables nothing. This is also what makes the
# pgAudit output (cloud-sql module) visible: it is a Cloud SQL Data Access log.
#
# Non-authoritative per service: each resource owns only its own service's
# entry in the project policy's `auditConfigs`, so it does not fight the
# google_project_iam_member bindings elsewhere. (It WOULD fight a
# google_project_iam_policy, which this config deliberately never uses.)

resource "google_project_iam_audit_config" "data_access" {
  for_each = toset(var.audited_services)

  project = var.project_id
  service = each.key

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# --- 2. Retained, optionally locked, bucket ---
#
# !!! `locked = true` IS IRREVERSIBLE. !!!
# A locked bucket's retention can never be changed, the bucket cannot be
# deleted until the last entry in it ages out, and the lock cannot be lifted.
# `tofu destroy` on a locked environment fails at this resource. That is the
# point — it is what makes the log tamper-evident — so it is off by default and
# switched on per environment in env/*.tfvars (prod only).

resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = var.region
  bucket_id      = "${var.base_prefix}-audit"
  retention_days = var.retention_days
  locked         = var.locked
  description    = "Cloud Audit Logs (Admin Activity, Data Access, System Event, Policy Denied), retained ${var.retention_days} days for CASA 6.7.1. Routed by the ${var.base_prefix}-audit sink."
}

# --- 3. Sink ---
#
# Every Cloud Audit Log in the project, not only the three services above:
# Admin Activity for IAM, logging and everything else is exactly what an
# assessor asks to see, and it is small. A same-project log-bucket
# destination needs no IAM grant for the writer identity.

resource "google_logging_project_sink" "audit" {
  project     = var.project_id
  name        = "${var.base_prefix}-audit"
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/${var.region}/buckets/${google_logging_project_bucket_config.audit.bucket_id}"
  filter      = "logName:\"/logs/cloudaudit.googleapis.com%2F\""
  description = "All Cloud Audit Logs to the retained ${google_logging_project_bucket_config.audit.bucket_id} bucket (CASA 6.7.1)."

  unique_writer_identity = true
}

# --- 4. Unexpected secret access ---
#
# Counts every AccessSecretVersion — successful or denied — whose caller is not
# one of the expected runtime service accounts. A caller with no principalEmail
# at all fails the NOT and is counted, which is the safe direction.
#
# This fires on every `tofu plan` by a human: the google provider refreshes each
# google_secret_manager_secret_version by reading its payload, and the monitoring
# module reads the PagerDuty key as a data source. That is intended — a human
# reading secret payloads is precisely the event the policy says must be seen —
# and each notification names the principal, so it is attributable to the apply.

locals {
  expected_accessor_clause = join(" OR ", [
    for p in var.expected_secret_accessors : "protoPayload.authenticationInfo.principalEmail=\"${p}\""
  ])

  unexpected_secret_access_filter = join("\n", [
    "logName:\"/logs/cloudaudit.googleapis.com%2Fdata_access\"",
    "protoPayload.serviceName=\"secretmanager.googleapis.com\"",
    "protoPayload.methodName:\"AccessSecretVersion\"",
    "NOT (${local.expected_accessor_clause})",
  ])
}

resource "google_logging_metric" "unexpected_secret_access" {
  project     = var.project_id
  name        = "${var.base_prefix}-unexpected-secret-access"
  description = "AccessSecretVersion by a principal outside the expected runtime service accounts (CASA 6.7.1)."
  filter      = local.unexpected_secret_access_filter

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "${var.base_prefix} unexpected secret access"

    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Caller's principal email"
    }
    labels {
      key         = "secret"
      value_type  = "STRING"
      description = "Secret ID (without the version)"
    }
  }

  label_extractors = {
    principal = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    secret    = "REGEXP_EXTRACT(protoPayload.resourceName, \"secrets/([^/]+)\")"
  }
}

resource "google_monitoring_alert_policy" "unexpected_secret_access" {
  count = var.alerts_enabled ? 1 : 0

  project      = var.project_id
  display_name = "[P1] ${var.base_prefix} Unexpected Secret Access"
  combiner     = "OR"

  conditions {
    display_name = "AccessSecretVersion by a non-runtime principal"

    condition_threshold {
      # Monitoring refuses a threshold filter without a resource.type. A
      # log-based metric's series carry the matched entry's resource, and
      # Secret Manager audit entries are all `audited_resource`.
      filter          = "metric.type = \"logging.googleapis.com/user/${google_logging_metric.unexpected_secret_access.name}\" AND resource.type = \"audited_resource\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.principal", "metric.label.secret"]
      }

      trigger {
        count = 1
      }
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      A principal outside the expected runtime service accounts read a Secret Manager payload.
      The incident names the principal and the secret.

      1. Your own `tofu plan`/`apply`, a `bin/db-shell.sh` session, or a documented break-glass read? Note it on the incident and close it.
      2. Otherwise treat it as a credential exposure: follow docs/compliance/casa/secrets-access-policy.md ("Responding to an alert") — rotate the secret, then find how the principal got access.

      Query: `logName:"cloudaudit.googleapis.com%2Fdata_access" protoPayload.methodName:"AccessSecretVersion"` in the ${google_logging_project_bucket_config.audit.bucket_id} bucket.
    EOT
  }

  notification_channels = var.notification_channels

  alert_strategy {
    auto_close = "86400s"
  }
}
