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

variable "dashboard_url" {
  description = "URL to redirect to after OAuth login (e.g. https://app.overslash.com)"
  type        = string
  default     = "/"
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
