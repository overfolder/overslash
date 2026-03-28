variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "environment" {
  type = string
}

variable "domain" {
  type    = string
  default = ""
}

variable "cloud_run_min_instances" {
  type = number
}

variable "cloud_run_max_instances" {
  type = number
}

variable "cloud_sql_tier" {
  type = string
}

variable "cloud_sql_disk_size_gb" {
  type = number
}

variable "docker_image" {
  type = string
}
