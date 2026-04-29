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

variable "pagerduty_integration_key" {
  type        = string
  default     = ""
  sensitive   = true
  description = "PagerDuty integration key. When set, P0 alerts also page. Empty = email-only."
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

