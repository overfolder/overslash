variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "tier" {
  type    = string
  default = "db-f1-micro"
}

variable "disk_size_gb" {
  type    = number
  default = 10
}

variable "zone" {
  type    = string
  default = "europe-west1-b"
}

variable "use_private_vpc" {
  type    = bool
  default = false
}

variable "private_network_id" {
  type    = string
  default = ""
}

variable "db_password_secret_id" {
  type = string
}

data "google_secret_manager_secret_version" "db_password" {
  secret  = var.db_password_secret_id
  project = var.project_id
}

resource "google_sql_database_instance" "db" {
  name             = "${var.base_prefix}-db"
  database_version = "POSTGRES_16"
  region           = var.region
  project          = var.project_id

  deletion_protection = false

  settings {
    tier              = var.tier
    disk_size         = var.disk_size_gb
    disk_autoresize   = true
    availability_type = "ZONAL"

    location_preference {
      zone = var.zone
    }

    ip_configuration {
      # Private VPC mode: private IP only
      # Auth Proxy mode: public IP (secured by IAM, no open access)
      ipv4_enabled                                  = !var.use_private_vpc
      private_network                               = var.use_private_vpc ? var.private_network_id : null
      enable_private_path_for_google_cloud_services = var.use_private_vpc
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 7
      }
    }

    database_flags {
      name  = "max_connections"
      value = "100"
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 4
      update_track = "stable"
    }
  }
}

resource "google_sql_database" "db" {
  name     = "overslash"
  instance = google_sql_database_instance.db.name
  project  = var.project_id
}

resource "google_sql_user" "db" {
  name     = "overslash"
  instance = google_sql_database_instance.db.name
  project  = var.project_id
  password = data.google_secret_manager_secret_version.db_password.secret_data
}

output "connection_name" {
  value = google_sql_database_instance.db.connection_name
}

output "instance_name" {
  value = google_sql_database_instance.db.name
}

output "private_ip" {
  value = google_sql_database_instance.db.private_ip_address
}

output "db_name" {
  value = google_sql_database.db.name
}

output "db_user" {
  value = google_sql_user.db.name
}
