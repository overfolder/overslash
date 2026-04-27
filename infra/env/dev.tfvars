project_id = "overslash-dev"
region     = "europe-west1"
env        = "dev"

domain           = "api.dev.overslash.com"
dashboard_origin = "https://app.dev.overslash.com"
dashboard_url    = "https://app.dev.overslash.com"

# Cloud SQL — minimum viable
cloud_sql_tier         = "db-f1-micro"
cloud_sql_disk_size_gb = 10
cloud_sql_zone         = "europe-west1-b"

# Cloud Run — scale to zero, minimal resources
cloud_run_cpu           = "1"
cloud_run_memory        = "512Mi"
cloud_run_min_instances = 0
cloud_run_max_instances = 3

# Networking — Auth Proxy mode (no VPC connector cost)
use_private_vpc = false

# Cloud Build
github_owner  = "overfolder"
github_repo   = "overslash"
github_branch = "^dev$"

# Cost saving — shut down DB on Spanish nights
enable_infra_scheduler     = true
infra_scheduler_stop_cron  = "0 23 * * *"
infra_scheduler_start_cron = "0 7 * * *"

# Optional
enable_valkey = false
enable_dns    = false
