variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
  default     = "europe-west1"
}

variable "env" {
  description = "Environment name. Defaults to the current tofu workspace name."
  type        = string
  default     = ""
}

variable "domain" {
  description = "Domain name for the service (e.g. api.overslash.com)"
  type        = string
  default     = ""
}

variable "dashboard_origin" {
  description = "Comma-separated allowed CORS origins for the dashboard (e.g. https://app.overslash.com)"
  type        = string
  default     = "*localhost*"
}

variable "mcp_extra_origins" {
  description = "Additional CORS origins allowed only on /mcp + /.well-known/oauth-* + /oauth/* (e.g. http://localhost:6274 for MCP Inspector). Does NOT widen CORS on the rest of the API."
  type        = string
  default     = ""
}

variable "dashboard_url" {
  description = "URL to redirect to after OAuth login (e.g. https://app.overslash.com)"
  type        = string
  default     = "/"
}

variable "enable_dev_auth" {
  description = "Enable DEV_AUTH bypass login on Cloud Run (dev only)"
  type        = bool
  default     = false
}

# --- Feature flags ---

variable "use_private_vpc" {
  description = "Use VPC private networking for Cloud SQL (true) or Cloud SQL Auth Proxy over public IP (false)"
  type        = bool
  default     = false
}

variable "enable_valkey" {
  description = "Enable Memorystore Valkey for webhooks/pub-sub"
  type        = bool
  default     = false
}

variable "enable_dns" {
  description = "Enable Cloud DNS managed zone"
  type        = bool
  default     = false
}

variable "enable_infra_scheduler" {
  description = "Enable Cloud Scheduler to stop/start Cloud SQL on a cron (saves cost)"
  type        = bool
  default     = false
}

variable "infra_scheduler_stop_cron" {
  description = "Cron to stop Cloud SQL (Europe/Madrid timezone)"
  type        = string
  default     = "0 23 * * *"
}

variable "infra_scheduler_start_cron" {
  description = "Cron to start Cloud SQL (Europe/Madrid timezone)"
  type        = string
  default     = "0 7 * * 1-5"
}

# --- Cloud SQL ---

variable "cloud_sql_zone" {
  description = "Preferred zone for Cloud SQL (e.g. europe-west1-b)"
  type        = string
  default     = "europe-west1-b"
}

variable "cloud_sql_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-f1-micro"
}

variable "cloud_sql_disk_size_gb" {
  description = "Cloud SQL disk size in GB"
  type        = number
  default     = 10
}

# --- Cloud Run ---

variable "cloud_run_cpu" {
  description = "Cloud Run CPU allocation (e.g. 1, 2)"
  type        = string
  default     = "1"
}

variable "cloud_run_memory" {
  description = "Cloud Run memory allocation (e.g. 256Mi, 512Mi)"
  type        = string
  default     = "512Mi"
}

variable "cloud_run_min_instances" {
  description = "Minimum Cloud Run instances"
  type        = number
  default     = 0
}

variable "cloud_run_max_instances" {
  description = "Maximum Cloud Run instances"
  type        = number
  default     = 3
}

# --- Cloud Build ---

variable "github_owner" {
  description = "GitHub repository owner for Cloud Build trigger"
  type        = string
  default     = "overfolder"
}

variable "github_repo" {
  description = "GitHub repository name for Cloud Build trigger"
  type        = string
  default     = "overslash"
}

variable "github_branch" {
  description = "Branch pattern to trigger builds"
  type        = string
  default     = "^master$"
}

# --- Redis ---

variable "valkey_memory_size_gb" {
  description = "Redis instance memory size in GB"
  type        = number
  default     = 1
}

# --- oversla.sh shortener ---

variable "enable_shortener" {
  description = "Deploy the oversla.sh URL shortener Cloud Run service. Requires enable_valkey=true and use_private_vpc=true."
  type        = bool
  default     = false
}

variable "shortener_domain" {
  description = "Custom domain for the shortener (e.g. oversla.sh). Empty = no domain mapping."
  type        = string
  default     = ""
}

variable "shortener_base_url" {
  description = "Public base URL used in short_url responses (e.g. https://oversla.sh)."
  type        = string
  default     = ""
}

variable "shortener_cpu" {
  description = "Cloud Run CPU for the shortener"
  type        = string
  default     = "1"
}

variable "shortener_memory" {
  description = "Cloud Run memory for the shortener"
  type        = string
  default     = "256Mi"
}

variable "shortener_max_instances" {
  description = "Max Cloud Run instances for the shortener"
  type        = number
  default     = 3
}

variable "shortener_root_redirect_url" {
  description = "URL that `GET /` redirects to on the shortener domain. Empty = 404 on root."
  type        = string
  default     = ""
}

# --- Billing ---

variable "cloud_billing" {
  description = "Enable Stripe billing gate for Team org creation. Requires Stripe secrets in Secret Manager."
  type        = bool
  default     = false
}

variable "stripe_eur_lookup_key" {
  description = "Stripe lookup key for the EUR seat price. The literal price_… ID is resolved at server startup. Default: overslash_seat_eur."
  type        = string
  default     = "overslash_seat_eur"
}

variable "stripe_usd_lookup_key" {
  description = "Stripe lookup key for the USD seat price. Default: overslash_seat_usd."
  type        = string
  default     = "overslash_seat_usd"
}

# --- Monitoring ---

variable "alert_email" {
  description = "Email that receives every alert. Required for the monitoring module."
  type        = string
  default     = ""
}

variable "pagerduty_integration_key" {
  description = "PagerDuty service integration key. When set, P0 alerts also page; empty = email-only."
  type        = string
  default     = ""
  sensitive   = true
}

variable "monthly_budget_usd" {
  description = "Monthly billing budget in USD. Triggers email alerts at 50%/80%/100%."
  type        = number
  default     = 200
}

variable "billing_account_id" {
  description = "GCP billing account ID. Empty = skip the billing-budget alert."
  type        = string
  default     = ""
}

variable "enable_metrics_sidecar" {
  description = "Run the OTel sidecar that scrapes /internal/metrics into Google Managed Prometheus."
  type        = bool
  default     = true
}
