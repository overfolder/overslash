variable "project_id" {
  type = string
}

variable "region" {
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

variable "private_network_id" {
  type = string
}

variable "db_password_secret_id" {
  type = string
}

# Read the generated DB password from Secret Manager
data "google_secret_manager_secret_version" "db_password" {
  secret  = var.db_password_secret_id
  project = var.project_id
}

resource "google_sql_database_instance" "overslash" {
  name             = "overslash-postgres"
  database_version = "POSTGRES_16"
  region           = var.region
  project          = var.project_id

  deletion_protection = true

  settings {
    tier              = var.tier
    disk_size         = var.disk_size_gb
    disk_autoresize   = true
    availability_type = "ZONAL"
    location_preference {
      zone = var.zone
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = var.private_network_id
      enable_private_path_for_google_cloud_services = true
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

resource "google_sql_database" "overslash" {
  name     = "overslash"
  instance = google_sql_database_instance.overslash.name
  project  = var.project_id
}

resource "google_sql_user" "overslash" {
  name     = "overslash"
  instance = google_sql_database_instance.overslash.name
  project  = var.project_id
  password = data.google_secret_manager_secret_version.db_password.secret_data
}

output "connection_name" {
  value = google_sql_database_instance.overslash.connection_name
}

output "private_ip" {
  value = google_sql_database_instance.overslash.private_ip_address
}

output "db_name" {
  value = google_sql_database.overslash.name
}

output "db_user" {
  value = google_sql_user.overslash.name
}
