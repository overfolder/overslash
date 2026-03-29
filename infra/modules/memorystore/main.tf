variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "memory_size_gb" {
  type    = number
  default = 1
}

variable "authorized_network" {
  type = string
}

resource "google_redis_instance" "overslash" {
  name           = "overslash-redis"
  project        = var.project_id
  region         = var.region
  tier           = "BASIC"
  memory_size_gb = var.memory_size_gb
  redis_version  = "REDIS_7_0"

  authorized_network = var.authorized_network

  display_name = "Overslash Redis"
}

output "redis_host" {
  value = google_redis_instance.overslash.host
}

output "redis_port" {
  value = tostring(google_redis_instance.overslash.port)
}
