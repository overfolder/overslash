variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
  default     = "europe-west1"
}

variable "env" {
  description = "Environment name. Defaults to the current tofu workspace name."
  type        = string
  default     = ""
}

variable "domain" {
  description = "Domain name for the service (e.g. api.overslash.com)"
  type        = string
  default     = ""
}

variable "app_host_suffix" {
  description = "Apex for the dashboard subdomain surface (e.g. app.overslash.com). Empty disables wildcard routing on this surface."
  type        = string
  default     = ""
}

variable "api_host_suffix" {
  description = "Apex for the programmatic / MCP / OAuth-AS subdomain surface (e.g. api.overslash.com). Empty disables wildcard routing here."
  type        = string
  default     = ""
}

variable "session_cookie_domain" {
  description = "Domain attribute for the session cookie. Typically a leading dot + app_host_suffix (e.g. .app.overslash.com) so the cookie is shared across org subdomains."
  type        = string
  default     = ""
}

variable "enable_api_lb" {
  description = "Provision a global HTTPS LB with wildcard managed cert in front of Cloud Run (required for *.api.<apex> routing at scale)."
  type        = bool
  default     = false
}

variable "extra_api_domain_mappings" {
  description = "No-LB path: list of fully-qualified hostnames to expose via 1-1 google_cloud_run_domain_mapping (e.g. [\"acme.api.dev.overslash.com\"]). Used when enable_api_lb=false to map a small set of per-org subdomains without standing up a global LB. DNS for each entry must already point at Cloud Run (CNAME ghs.googlehosted.com) and the apex must be Search-Console verified."
  type        = list(string)
  default     = []
}

variable "dashboard_origin" {
  description = "Comma-separated allowed CORS origins for the dashboard. Wildcards `https://*.app.overslash.com` allowed."
  type        = string
  default     = "*localhost*"
}

variable "mcp_extra_origins" {
  description = "Additional CORS origins allowed only on /mcp + /.well-known/oauth-* + /oauth/* (e.g. http://localhost:6274 for MCP Inspector). Does NOT widen CORS on the rest of the API."
  type        = string
  default     = ""
}

variable "dashboard_url" {
  description = "URL to redirect to after OAuth login (e.g. https://app.overslash.com)"
  type        = string
  default     = "/"
}

variable "enable_dev_auth" {
  description = "Enable DEV_AUTH bypass login on Cloud Run (dev only)"
  type        = bool
  default     = false
}

variable "enable_live_map" {
  description = "Enable the Live Map (/map) and the per-call `action.*` events it animates (OVERSLASH_LIVE_MAP). Dev only — one durable events row per action call. See D57."
  type        = bool
  default     = false
}

variable "enable_magic_link" {
  description = "Enable passwordless email magic-link login (MAGIC_LINK_ENABLED). Default-on: it's the working login on an env with no external IdP configured."
  type        = bool
  default     = true
}

variable "enable_google_login" {
  description = "Provision + inject the Google LOGIN OAuth client (Sign-in with Google). Default-on to preserve existing behavior; populate the secret values post-apply."
  type        = bool
  default     = true
}

variable "enable_github_login" {
  description = "Provision + inject the GitHub LOGIN OAuth App (Sign-in with GitHub). Off by default; enable per-env via tfvars and populate the secret values post-apply."
  type        = bool
  default     = false
}

variable "rust_log" {
  description = "RUST_LOG value for the API container. Defaults to `info`; set to `debug` in dev for verbose logging."
  type        = string
  default     = "info"
}

variable "vercel_preview_origin_regex" {
  description = "Regex matching Vercel preview-deployment URLs allowed to use the OAuth handoff (dev-only). Empty = feature off (production must leave it empty). Combined with OVERSLASH_ENV=dev as a defense-in-depth gate; a non-dev environment never advertises the endpoint, even if this is set by mistake."
  type        = string
  default     = ""
}

variable "connection_return_url_hosts" {
  description = "Comma-separated hostnames (no scheme, no path) allowed as OAuth return_url targets after the code exchange. E.g. `api-dev.overfolder.com` for the overfolder dev tenant. Empty = feature disabled (Overslash returns JSON; no redirect)."
  type        = string
  default     = ""
}

# --- Feature flags ---

variable "use_private_vpc" {
  description = "Use VPC private networking for Cloud SQL (true) or Cloud SQL Auth Proxy over public IP (false)"
  type        = bool
  default     = false
}

variable "enable_valkey" {
  description = "Enable Memorystore Valkey for webhooks/pub-sub"
  type        = bool
  default     = false
}

variable "enable_dns" {
  description = "Enable Cloud DNS managed zone"
  type        = bool
  default     = false
}

variable "enable_infra_scheduler" {
  description = "Enable Cloud Scheduler to stop/start Cloud SQL on a cron (saves cost)"
  type        = bool
  default     = false
}

variable "infra_scheduler_stop_cron" {
  description = "Cron to stop Cloud SQL (Europe/Madrid timezone)"
  type        = string
  default     = "0 23 * * *"
}

variable "infra_scheduler_start_cron" {
  description = "Cron to start Cloud SQL (Europe/Madrid timezone)"
  type        = string
  default     = "0 7 * * 1-5"
}

# --- Cloud SQL ---

variable "cloud_sql_zone" {
  description = "Preferred zone for Cloud SQL (e.g. europe-west1-b)"
  type        = string
  default     = "europe-west1-b"
}

variable "cloud_sql_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-f1-micro"
}

variable "cloud_sql_disk_size_gb" {
  description = "Cloud SQL disk size in GB"
  type        = number
  default     = 10
}

# --- Cloud Run ---

variable "cloud_run_cpu" {
  description = "Cloud Run CPU allocation (e.g. 1, 2)"
  type        = string
  default     = "1"
}

variable "cloud_run_memory" {
  description = "Cloud Run memory allocation (e.g. 256Mi, 512Mi)"
  type        = string
  default     = "512Mi"
}

variable "cloud_run_min_instances" {
  description = "Minimum Cloud Run instances"
  type        = number
  default     = 0
}

variable "cloud_run_max_instances" {
  description = "Maximum Cloud Run instances"
  type        = number
  default     = 3
}

# --- Cloud Build ---

variable "github_owner" {
  description = "GitHub repository owner for Cloud Build trigger"
  type        = string
  default     = "overfolder"
}

variable "github_repo" {
  description = "GitHub repository name for Cloud Build trigger"
  type        = string
  default     = "overslash"
}

variable "github_branch" {
  description = "Branch pattern to trigger builds"
  type        = string
  default     = "^master$"
}

# --- Redis ---

variable "valkey_memory_size_gb" {
  description = "Redis instance memory size in GB"
  type        = number
  default     = 1
}

# --- oversla.sh shortener ---

variable "read_oauth_credentials_from_env" {
  description = "Set OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1 on the API Cloud Run service (tier-4 env-var fallback for OAUTH_GOOGLE_* credentials). Enable in dev only."
  type        = bool
  default     = false
}

variable "enable_shortener_client" {
  description = "Wire OVERSLA_SH_BASE_URL + OVERSLA_SH_API_KEY into the API Cloud Run service so it can mint short links. Set oversla_sh_base_url to the target shortener (e.g. https://oversla.sh for prod). The secret must be populated via gcloud before apply."
  type        = bool
  default     = false
}

variable "oversla_sh_base_url" {
  description = "Base URL of the oversla.sh shortener the API client calls (e.g. https://oversla.sh). Only used when enable_shortener_client=true."
  type        = string
  default     = ""
}

variable "enable_shortener" {
  description = "Deploy the oversla.sh URL shortener Cloud Run service. Requires enable_valkey=true and use_private_vpc=true."
  type        = bool
  default     = false
}

variable "shortener_domain" {
  description = "Custom domain for the shortener (e.g. oversla.sh). Empty = no domain mapping."
  type        = string
  default     = ""
}

variable "shortener_base_url" {
  description = "Public base URL used in short_url responses (e.g. https://oversla.sh)."
  type        = string
  default     = ""
}

variable "shortener_cpu" {
  description = "Cloud Run CPU for the shortener"
  type        = string
  default     = "1"
}

variable "shortener_memory" {
  description = "Cloud Run memory for the shortener"
  type        = string
  default     = "256Mi"
}

variable "shortener_max_instances" {
  description = "Max Cloud Run instances for the shortener"
  type        = number
  default     = 3
}

variable "shortener_root_redirect_url" {
  description = "URL that `GET /` redirects to on the shortener domain. Empty = 404 on root."
  type        = string
  default     = ""
}

# --- overfwd (shared Mailbox Gateway) ---

variable "enable_overfwd" {
  description = "Deploy the shared overfwd Mailbox Gateway that backs `services/email.yaml`. Also provisions the Docker Hub pull-through mirror and wires the API's platform-credential rung so no org has to store the gateway key."
  type        = bool
  default     = false
}

variable "overfwd_image" {
  description = "overfwd image path *relative to the Docker Hub mirror*, digest-pinned (e.g. `angelmanuel/overfwd@sha256:…`). A moving tag would be an unreviewed third-party code change reaching production on the next revision roll, so a digest is required."
  type        = string
  # v0.4.0 — the release where an unparseable IMAP SEARCH key returns a 400
  # naming the fix instead of `200 []`, an empty key means ALL, and /email/search
  # answers `{results, total, truncated}` rather than a bare array. The `search`
  # action's description in `services/email.yaml` documents that contract, so a
  # downgrade would make the shipped template lie to agents.
  #
  # Still ≥ v0.3.0, which introduced OVERFWD_BLOCK_PRIVATE_ENDPOINTS — the
  # module turns that on and would fail closed against an older image.
  default = "angelmanuel/overfwd@sha256:adaf72343c74699ebdbb517d2e9e299f0631729379b527ef96c9a20f87d0989a"

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.overfwd_image))
    error_message = "overfwd_image must be digest-pinned (…@sha256:<64 hex chars>)."
  }
}

variable "overfwd_domain" {
  description = "Hostname the gateway serves (e.g. mailbox.overslash.com). Feeds BOTH the platform-key host gate and `OVERSLASH_TEMPLATE_VAR_MAILBOX_HOST`, which is what services/email.yaml's `servers[0]` resolves to (D44) — so the template and the key gate cannot drift. Empty = no domain mapping, no platform rung, and no `email` template."
  type        = string
  default     = ""
}

# Extra service-template variables beyond the ones this config derives itself
# (MAILBOX_HOST comes from overfwd_domain). Keyed WITHOUT the
# OVERSLASH_TEMPLATE_VAR_ prefix. Non-secret only — any tenant who can author a
# template can read these back. See D44.
variable "template_vars" {
  description = "Additional service-template variables, e.g. { METABASE_URL = \"https://metabase.example.com\" }. Non-secret only."
  type        = map(string)
  default     = {}
}

variable "overfwd_cpu" {
  description = "Cloud Run CPU for overfwd. Keep at 1: below one vCPU Cloud Run pins concurrency to 1."
  type        = string
  default     = "1"
}

variable "overfwd_memory" {
  description = "Cloud Run memory for overfwd. ~17MiB at rest; legal below 512Mi only because the module throttles CPU when idle. Raise in lockstep with overfwd_concurrency."
  type        = string
  default     = "256Mi"
}

variable "overfwd_min_instances" {
  description = "Min Cloud Run instances for overfwd. 0 scales to zero; a mailbox call then pays a cold start."
  type        = number
  default     = 0
}

variable "overfwd_max_instances" {
  description = "Max Cloud Run instances for overfwd"
  type        = number
  default     = 3
}

variable "overfwd_concurrency" {
  description = "Requests in flight per overfwd instance. Far below Cloud Run's default 80 because each in-flight `get` can hold a whole message in memory and the limit is 256Mi."
  type        = number
  default     = 8
}

# --- Billing ---

variable "cloud_billing" {
  description = "Enable Stripe billing gate for Team org creation. Requires Stripe secrets in Secret Manager."
  type        = bool
  default     = false
}

variable "stripe_eur_lookup_key" {
  description = "Stripe lookup key for the EUR seat price. The literal price_… ID is resolved at server startup. Default: overslash_seat_eur."
  type        = string
  default     = "overslash_seat_eur"
}

variable "stripe_usd_lookup_key" {
  description = "Stripe lookup key for the USD seat price. Default: overslash_seat_usd."
  type        = string
  default     = "overslash_seat_usd"
}

# --- Transactional email ---

variable "email_provider" {
  description = "Transactional-email provider. `resend` is the only recognised value today; empty (default) keeps the API on the NoopMailer fallback. Setting this without populating the `<base_prefix>-email-api-key` secret will fail validate_env at Cloud Run boot."
  type        = string
  default     = ""
}

variable "email_from" {
  description = "From address used on all outbound transactional email (e.g. no-reply@mail.overslash.com). Required when email_provider != \"\"."
  type        = string
  default     = ""
}

variable "email_reply_to" {
  description = "Optional Reply-To address. Empty leaves the provider's default."
  type        = string
  default     = ""
}

# --- Monitoring ---

variable "alert_email" {
  description = "Email that receives every alert. Required for the monitoring module."
  type        = string
  default     = ""
}

variable "pagerduty_enabled" {
  description = "Enable PagerDuty paging for P0 alerts. Requires the `<base_prefix>-pagerduty-integration-key` secret (e.g. overslash-prod-pagerduty-integration-key) to be populated in Secret Manager."
  type        = bool
  default     = false
}

variable "oauth_refresh_alert_enabled" {
  description = "Enable the OAuth refresh failure rate P1 alert. Leave false until overslash_oauth_events_total has been emitted at least once (GMP rejects the policy if the metric descriptor does not exist)."
  type        = bool
  default     = false
}

variable "upstream_error_alert_enabled" {
  description = "Enable the upstream error rate P1 alert. Leave false until overslash_upstream_responses_total has been emitted at least once (GMP rejects the policy if the metric descriptor does not exist)."
  type        = bool
  default     = false
}

variable "monthly_budget_usd" {
  description = "Monthly billing budget in USD. Triggers email alerts at 50%/80%/100%."
  type        = number
  default     = 200
}

variable "billing_account_id" {
  description = "GCP billing account ID. Empty = skip the billing-budget alert."
  type        = string
  default     = ""
}

variable "enable_metrics_sidecar" {
  description = "Run the OTel sidecar that scrapes /internal/metrics into Google Managed Prometheus."
  type        = bool
  default     = true
}
