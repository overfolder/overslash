variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment name (e.g. prod, staging)"
  type        = string
  default     = "prod"
}

variable "domain" {
  description = "Domain name for the service (e.g. api.overslash.com)"
  type        = string
  default     = ""
}

variable "enable_redis" {
  description = "Enable Memorystore Redis for webhooks/pub-sub"
  type        = bool
  default     = false
}

variable "enable_dns" {
  description = "Enable Cloud DNS managed zone"
  type        = bool
  default     = false
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

variable "cloud_run_cpu" {
  description = "Cloud Run CPU allocation (e.g. 1, 2)"
  type        = string
  default     = "1"
}

variable "cloud_run_memory" {
  description = "Cloud Run memory allocation (e.g. 512Mi, 1Gi)"
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
  default     = 10
}

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

variable "redis_memory_size_gb" {
  description = "Redis instance memory size in GB"
  type        = number
  default     = 1
}
