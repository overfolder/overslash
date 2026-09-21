variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "base_prefix" {
  type        = string
  description = "Prefix used for resource names (e.g. overslash-dev)."
}

variable "alert_email" {
  type        = string
  description = "Email address that receives every alert. Required."
}

variable "pagerduty_enabled" {
  type        = bool
  default     = false
  description = "When true, P0 alerts page PagerDuty via the EU GCM integration. Requires the secret named in `pagerduty_secret_id` to be populated."
}

variable "pagerduty_secret_id" {
  type        = string
  default     = ""
  description = "Secret Manager secret ID holding the PagerDuty (EU) integration key. Ignored unless `pagerduty_enabled = true`."
}

variable "api_domain" {
  type        = string
  default     = ""
  description = "Public domain of the API (e.g. api.overslash.com). Empty disables the uptime check + the API-down alert."
}

variable "api_service_name" {
  type        = string
  description = "Cloud Run service name for the API (used to filter Cloud Run metrics)."
}

variable "cloud_sql_instance_name" {
  type        = string
  description = "Cloud SQL instance name (used to build database_id labels)."
}

variable "monthly_budget_usd" {
  type        = number
  default     = 200
  description = "Monthly billing budget in USD. Triggers email alerts at 50%/80%/100%."
}

variable "billing_account_id" {
  type        = string
  default     = ""
  description = "GCP billing account ID. Empty = skip the billing-budget alert (project must be linked to a billing account for it to work)."
}

variable "oauth_refresh_alert_enabled" {
  type        = bool
  default     = false
  description = "Enable the OAuth refresh failure rate alert. GMP rejects the alert policy if overslash_oauth_events_total has never been emitted (no metric descriptor yet). Set true once at least one OAuth token refresh has been observed."
}

variable "upstream_error_alert_enabled" {
  type        = bool
  default     = false
  description = "Enable the upstream error rate alert. GMP rejects the alert policy if overslash_upstream_responses_total has never been emitted (no metric descriptor yet). Set true once at least one upstream response has been observed."
}

variable "api_latency_alert_enabled" {
  type        = bool
  default     = false
  description = "Enable the [P1] API Slow Requests alert. GMP rejects the alert policy until overslash_http_request_duration_seconds has been scraped *as a histogram* — before the release carrying set_buckets_for_metric, the metric exists only as a summary and has no _bucket series for the query to read. Set true once the histogram descriptor is visible in Metrics Explorer."
}
