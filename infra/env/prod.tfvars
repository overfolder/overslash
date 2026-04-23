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

# Networking — Auth Proxy mode (saves ~$7/mo VPC connector)
use_private_vpc = false

# Cloud Build
github_owner  = "overfolder"
github_repo   = "overslash"
github_branch = "^master$"

# Prod runs 24/7 — scheduler disabled.
enable_infra_scheduler     = false
infra_scheduler_stop_cron  = "0 23 * * *"
infra_scheduler_start_cron = "0 7 * * *"

# Optional
enable_valkey = false
enable_dns    = false

# MCP runtime (isolated Cloud Run service for third-party MCP servers).
# Off by default; flip on and fill in the SA + secret id below to deploy.
enable_mcp_runtime = false
# mcp_runtime_sa_email         = "overslash-mcp-runtime@<project>.iam.gserviceaccount.com"
# mcp_runtime_shared_secret_id = "OVERSLASH_MCP_RUNTIME_SHARED_SECRET"
# mcp_runtime_cpu              = "2"
# mcp_runtime_memory           = "4Gi"
# mcp_runtime_min_instances    = 1
# mcp_runtime_max_instances    = 3
