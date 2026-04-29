project_id = "overslash-dev"
region     = "europe-west1"
env        = "dev"

domain = ""

app_host_suffix       = "app.dev.overslash.com"
api_host_suffix       = "api.dev.overslash.com"
session_cookie_domain = ".app.dev.overslash.com"
enable_api_lb         = true

dashboard_origin = "https://app.dev.overslash.com,https://*.app.dev.overslash.com"
dashboard_url    = "https://app.dev.overslash.com"
enable_dev_auth  = false

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

# Billing — disabled in dev; enable for billing testing
cloud_billing = false
# Lookup keys default to overslash_seat_eur / overslash_seat_usd
# stripe_eur_lookup_key = "overslash_seat_eur"
# stripe_usd_lookup_key = "overslash_seat_usd"
