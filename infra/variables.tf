variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "environment" {
  type        = string
  description = "Environment name: dev, staging, or prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Must be dev, staging, or prod."
  }
}

variable "domain" {
  type        = string
  default     = ""
  description = "Custom domain for Cloud Run (e.g. api.overslash.com). Empty = no mapping."
}

variable "cloud_run_min_instances" {
  type    = number
  default = 1
}

variable "cloud_run_max_instances" {
  type    = number
  default = 5
}

variable "cloud_sql_tier" {
  type        = string
  default     = "db-f1-micro"
  description = "Cloud SQL machine type"
}

variable "cloud_sql_disk_size_gb" {
  type    = number
  default = 10
}

variable "docker_image" {
  type        = string
  description = "Full Docker image path including tag"
}
