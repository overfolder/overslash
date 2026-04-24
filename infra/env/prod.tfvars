project_id = "overslash"
region     = "europe-west1"
env        = "prod"

domain           = "api.overslash.com"
dashboard_origin = "https://app.overslash.com"
dashboard_url    = "https://app.overslash.com"

# Cloud SQL — minimum viable for pre-GA
cloud_sql_tier         = "db-f1-micro"
cloud_sql_disk_size_gb = 10
cloud_sql_zone         = "europe-west1-b"

# Cloud Run — scale to zero, minimal resources
cloud_run_cpu           = "1"
cloud_run_memory        = "512Mi"
cloud_run_min_instances = 0
cloud_run_max_instances = 3

# Networking — private VPC required for Memorystore/Valkey reachability
# (used by the oversla.sh shortener). Adds ~$7/mo for VPC connector.
use_private_vpc = true

# Cloud Build
github_owner  = "overfolder"
github_repo   = "overslash"
github_branch = "^master$"

# Prod runs 24/7 — scheduler disabled.
enable_infra_scheduler     = false
infra_scheduler_stop_cron  = "0 23 * * *"
infra_scheduler_start_cron = "0 7 * * *"

# Optional
enable_valkey    = true
enable_dns       = false
enable_shortener = true

# oversla.sh shortener config
shortener_base_url          = "https://oversla.sh"
shortener_domain            = "oversla.sh"
shortener_root_redirect_url = "https://www.overslash.com"
