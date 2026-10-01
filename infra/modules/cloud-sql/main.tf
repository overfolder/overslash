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

variable "db_password" {
  type      = string
  sensitive = true
}

resource "google_sql_database_instance" "db" {
  name             = "${var.base_prefix}-db"
  database_version = "POSTGRES_16"
  region           = var.region
  project          = var.project_id

  # Two separate locks. This one is Terraform's: `tofu destroy`, or a plan
  # that would replace the instance, fails before any API call. The one in
  # `settings` is the Cloud SQL API's own, so `gcloud sql instances delete`
  # and the console refuse too. Lifting either is a deliberate two-step:
  # set it false, apply, then delete.
  deletion_protection = true

  settings {
    tier              = var.tier
    disk_size         = var.disk_size_gb
    disk_autoresize   = true
    availability_type = "ZONAL"

    deletion_protection_enabled = true

    location_preference {
      zone = var.zone
    }

    ip_configuration {
      # Private VPC mode: private IP only
      # Auth Proxy mode: public IP (secured by IAM, no open access)
      ipv4_enabled                                  = !var.use_private_vpc
      private_network                               = var.use_private_vpc ? var.private_network_id : null
      enable_private_path_for_google_cloud_services = var.use_private_vpc

      # Refuse plaintext on direct connections (CASA 4.1.1). The Auth Proxy
      # is always TLS and is admitted under any mode, and it is how our
      # clients arrive: the Cloud Run API (migrations included) and the
      # metrics-exporter job via the `/cloudsql` socket volume, humans via
      # `bin/db-shell.sh`. BigQuery federation (`modules/bi`) is Google's
      # managed path, authorised by its connection's `cloudsql.client`
      # service account; the runbook smoke-tests it after apply. What this
      # closes is anything connecting straight to the IP. The client
      # certificate is not checked — that is TRUSTED_CLIENT_CERTIFICATE_REQUIRED.
      ssl_mode = "ENCRYPTED_ONLY"
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

    # --- Database auditing (CASA 6.7.1) ---
    #
    # Connection lifecycle goes to the postgres log. pgAudit writes to Cloud
    # Logging as Data Access audit logs, so nothing is recorded until the
    # project's audit config turns those on (TODO.md §1.6), and the extension
    # must also exist: `CREATE EXTENSION pgaudit;` once, as `overslash`
    # (docs/runbooks/cloud-sql-hardening.md). Flipping enable_pgaudit
    # restarts the instance.
    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }

    # Schema changes and privilege changes — who altered the database, not
    # what data it served. `read`/`write` would log every request the API
    # makes and duplicate what the application audit log already records.
    database_flags {
      name  = "pgaudit.log"
      value = "ddl,role"
    }

    # `role` logs the API's boot-time `ALTER ROLE bi … PASSWORD '<plaintext>'`
    # (overslash_db::bi). Masking turns every literal into `$n` before the
    # statement is written, so the password never reaches Cloud Logging.
    database_flags {
      name  = "cloudsql.pgaudit_mask_literals"
      value = "on"
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
  password = var.db_password
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
