project_id = "overslash-dev"
region     = "europe-west1"
env        = "dev"

# Apex API host. Kept as a real Cloud Run domain mapping so the apex stays
# reachable when `enable_api_lb = false` (dev runs without GCLB to save cost).
domain = "api.dev.overslash.com"

app_host_suffix       = "app.dev.overslash.com"
api_host_suffix       = "api.dev.overslash.com"
session_cookie_domain = ".app.dev.overslash.com"

# Dev runs without the wildcard-cert GCLB. Per-org API subdomains are
# instead created as 1-1 Cloud Run domain mappings via
# `extra_api_domain_mappings` below, which keeps cost at zero and avoids
# provisioning a global LB just to host a couple of dogfood orgs.
enable_api_lb             = false
extra_api_domain_mappings = []

# Lets a locally-run MCP Inspector (default port 6274) complete the OAuth
# handshake against the dev API. Scoped to /mcp + /.well-known/oauth-* +
# /oauth/* only — does NOT widen CORS on /v1/*.
mcp_extra_origins = "http://localhost:6274"

dashboard_origin = "https://app.dev.overslash.com,https://*.app.dev.overslash.com"
dashboard_url    = "https://app.dev.overslash.com"
enable_dev_auth  = false

# Vercel preview-deployment OAuth handoff. Lets the dashboard's Vercel
# previews complete Google sign-in by adopting a session cookie minted on
# api.dev.overslash.com via a one-time code rather than a (cross-origin)
# Set-Cookie. Pinned to our team's preview URL pattern so a random Vercel
# tenant can't piggyback. Combined with OVERSLASH_ENV=dev (set from var.env)
# as defense-in-depth — production must NEVER set this var.
vercel_preview_origin_regex = "^https://overslash-[a-z0-9-]+-amanuelmartincanto-2204s-projects\\.vercel\\.app$"

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
cloud_billing = true
# Lookup keys default to overslash_seat_eur / overslash_seat_usd
# stripe_eur_lookup_key = "overslash_seat_eur"
# stripe_usd_lookup_key = "overslash_seat_usd"

alert_email = "alert@overspiral.com"
