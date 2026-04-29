project_id = "overslash"
region     = "europe-west1"
env        = "prod"

# Empty `domain` skips the single-host google_cloud_run_domain_mapping in
# favor of the wildcard GCLB stack (see `enable_api_lb`).
domain = ""

# Wildcard subdomain surfaces.
app_host_suffix       = "app.overslash.com"
api_host_suffix       = "api.overslash.com"
session_cookie_domain = ".app.overslash.com"
enable_api_lb         = true

# Wildcard CORS so `<slug>.app.overslash.com` browser sessions can call the
# API cross-origin without enumerating slugs.
dashboard_origin = "https://app.overslash.com,https://*.app.overslash.com"
dashboard_url    = "https://app.overslash.com"
enable_dev_auth  = false

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

# Billing — Stripe lookup keys default to overslash_seat_eur / overslash_seat_usd.
# Set the same `lookup_key` on the corresponding Price in Stripe Dashboard so the
# server can resolve the literal price_… ID at startup. Override here only if you
# pick different lookup-key names.
# Secrets (sk_live_... and whsec_...) are populated via:
#   gcloud secrets versions add overslash-prod-stripe-secret-key --data-file=-
#   gcloud secrets versions add overslash-prod-stripe-webhook-secret --data-file=-
cloud_billing = true
# stripe_eur_lookup_key = "overslash_seat_eur"
# stripe_usd_lookup_key = "overslash_seat_usd"
