# Enable required GCP APIs
resource "google_project_service" "apis" {
  for_each = toset(concat(
    [
      "run.googleapis.com",
      "sqladmin.googleapis.com",
      "artifactregistry.googleapis.com",
      "cloudbuild.googleapis.com",
      "secretmanager.googleapis.com",
      "compute.googleapis.com",
      "cloudscheduler.googleapis.com",
      "monitoring.googleapis.com",
      "billingbudgets.googleapis.com",
    ],
    var.use_private_vpc ? [
      "servicenetworking.googleapis.com",
      "vpcaccess.googleapis.com",
    ] : [],
    var.enable_dns ? ["dns.googleapis.com"] : [],
    var.enable_api_lb ? ["certificatemanager.googleapis.com"] : [],
    var.enable_valkey ? ["redis.googleapis.com"] : [],
  ))

  service            = each.key
  disable_on_destroy = false
}

# --- Networking (only when using private VPC) ---
module "networking" {
  count = var.use_private_vpc ? 1 : 0

  source      = "./modules/networking"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  depends_on = [google_project_service.apis]
}

# --- IAM ---
module "iam" {
  source      = "./modules/iam"
  project_id  = var.project_id
  base_prefix = local.base_prefix

  depends_on = [google_project_service.apis]
}

# --- Artifact Registry ---
module "artifact_registry" {
  source      = "./modules/artifact-registry"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  # overfwd is the one image we deploy but do not build; the mirror keeps its
  # pull off Docker Hub's availability and rate limits.
  enable_docker_hub_remote = var.enable_overfwd

  depends_on = [google_project_service.apis]
}

# --- Secret Manager ---
module "secret_manager" {
  source      = "./modules/secret-manager"
  project_id  = var.project_id
  base_prefix = local.base_prefix

  cloud_run_sa_email = module.iam.cloud_run_sa_email

  enable_google_login = var.enable_google_login
  enable_github_login = var.enable_github_login

  depends_on = [google_project_service.apis]
}

# --- Cloud SQL ---
module "cloud_sql" {
  source      = "./modules/cloud-sql"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  tier         = var.cloud_sql_tier
  disk_size_gb = var.cloud_sql_disk_size_gb
  zone         = var.cloud_sql_zone

  use_private_vpc    = var.use_private_vpc
  private_network_id = var.use_private_vpc ? module.networking[0].vpc_id : ""

  db_password = module.secret_manager.db_password_value

  # module.networking must be fully applied (not just the VPC, but the
  # google_service_networking_connection peering resource) before Cloud
  # SQL can be flipped to private_network. The implicit dep through
  # private_network_id only waits for VPC creation, which resolves before
  # the peering is established, causing NETWORK_NOT_PEERED on the SQL
  # update. Explicit depends_on forces the correct order.
  depends_on = [
    google_project_service.apis,
    module.networking,
  ]
}

# --- Cloud Run ---
module "cloud_run" {
  source      = "./modules/cloud-run"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  service_account_email = module.iam.cloud_run_sa_email

  use_private_vpc  = var.use_private_vpc
  vpc_connector_id = var.use_private_vpc ? module.networking[0].vpc_connector_id : ""

  image = "${var.region}-docker.pkg.dev/${var.project_id}/${module.artifact_registry.repository_name}/overslash-api:latest"

  cpu           = var.cloud_run_cpu
  memory        = var.cloud_run_memory
  min_instances = var.cloud_run_min_instances
  max_instances = var.cloud_run_max_instances

  cloud_sql_connection_name = module.cloud_sql.connection_name

  # Secret references
  db_password_secret_id                   = module.secret_manager.db_password_secret_id
  encryption_key_secret_id                = module.secret_manager.encryption_key_secret_id
  signing_key_secret_id                   = module.secret_manager.signing_key_secret_id
  oauth_client_id_secret_id               = module.secret_manager.oauth_client_id_secret_id
  oauth_client_secret_secret_id           = module.secret_manager.oauth_client_secret_secret_id
  github_auth_client_id_secret_id         = module.secret_manager.github_auth_client_id_secret_id
  github_auth_client_secret_secret_id     = module.secret_manager.github_auth_client_secret_secret_id
  google_services_client_id_secret_id     = module.secret_manager.google_services_client_id_secret_id
  google_services_client_secret_secret_id = module.secret_manager.google_services_client_secret_secret_id

  # Billing
  cloud_billing                   = var.cloud_billing
  stripe_eur_lookup_key           = var.stripe_eur_lookup_key
  stripe_usd_lookup_key           = var.stripe_usd_lookup_key
  stripe_secret_key_secret_id     = module.secret_manager.stripe_secret_key_secret_id
  stripe_webhook_secret_secret_id = module.secret_manager.stripe_webhook_secret_secret_id

  # Transactional email
  email_provider          = var.email_provider
  email_from              = var.email_from
  email_reply_to          = var.email_reply_to
  email_api_key_secret_id = module.secret_manager.email_api_key_secret_id

  db_user = module.cloud_sql.db_user
  db_name = module.cloud_sql.db_name

  domain                    = var.domain
  app_host_suffix           = var.app_host_suffix
  api_host_suffix           = var.api_host_suffix
  session_cookie_domain     = var.session_cookie_domain
  dashboard_origin          = var.dashboard_origin
  mcp_extra_origins         = var.mcp_extra_origins
  dashboard_url             = var.dashboard_url
  enable_dev_auth           = var.enable_dev_auth
  enable_magic_link         = var.enable_magic_link
  extra_api_domain_mappings = var.extra_api_domain_mappings

  overslash_env               = var.env
  vercel_preview_origin_regex = var.vercel_preview_origin_regex

  connection_return_url_hosts = var.connection_return_url_hosts

  redis_host = var.enable_valkey && var.use_private_vpc ? module.memorystore[0].redis_host : ""
  redis_port = var.enable_valkey && var.use_private_vpc ? module.memorystore[0].redis_port : ""

  enable_metrics_sidecar = var.enable_metrics_sidecar
  rust_log               = var.rust_log

  read_oauth_credentials_from_env = var.read_oauth_credentials_from_env

  # oversla.sh client
  enable_shortener_client     = var.enable_shortener_client
  oversla_sh_base_url         = var.oversla_sh_base_url
  shortener_api_key_secret_id = module.secret_manager.shortener_api_key_secret_id

  # Shared Mailbox Gateway: fill the `email` template's org-source gateway slot
  # from platform config so no org has to hold the key (D39). Host-gated to the
  # deployment below, so an org pointing its instances at its own overfwd never
  # receives it.
  platform_gateway_secret_name   = var.enable_overfwd ? "overfwd_gateway_key" : ""
  platform_gateway_host          = var.enable_overfwd ? var.overfwd_domain : ""
  platform_gateway_key_secret_id = var.enable_overfwd ? module.secret_manager.overfwd_gateway_key_secret_id : ""

  depends_on = [
    module.cloud_sql,
    module.secret_manager,
    module.artifact_registry,
  ]
}

# --- Monitoring (dashboards always; alerts gated on alert_email) ---
module "monitoring" {
  source      = "./modules/monitoring"
  project_id  = var.project_id
  base_prefix = local.base_prefix

  alert_email                  = var.alert_email
  pagerduty_enabled            = var.pagerduty_enabled
  pagerduty_secret_id          = module.secret_manager.pagerduty_integration_key_secret_id
  oauth_refresh_alert_enabled  = var.oauth_refresh_alert_enabled
  upstream_error_alert_enabled = var.upstream_error_alert_enabled
  api_domain                   = var.domain
  api_service_name             = module.cloud_run.service_name
  cloud_sql_instance_name      = module.cloud_sql.instance_name
  monthly_budget_usd           = var.monthly_budget_usd
  billing_account_id           = var.billing_account_id

  depends_on = [
    google_project_service.apis,
    module.cloud_run,
    module.cloud_sql,
  ]
}

# --- API Load Balancer (global HTTPS LB with wildcard Certificate Manager cert) ---
#
# Required for `*.api.<apex>` routing at scale — Cloud Run's native domain
# mapping is single-domain and DNS-TXT-validated, which doesn't grow with
# tens of orgs. When `enable_api_lb=true` this module fronts Cloud Run with
# a global HTTPS LB + Certificate Manager wildcard cert (and the operator
# should leave `domain=""` on the cloud-run module).
#
# Wildcard issuance needs DNS-01, so a CNAME challenge has to live in the
# zone covering `api_apex`. When `enable_dns` is also on, we hand the api-lb
# module the zone name and the record is published automatically; otherwise
# the module exposes the record values via outputs and the operator wires
# them up in their external DNS provider.
#
# When `enable_api_lb=false` (dev), the cloud-run module instead provisions
# 1-1 `google_cloud_run_domain_mapping` resources for each entry in
# `extra_api_domain_mappings` (plus the apex `domain` if non-empty), which
# keeps the bill at zero for a small dogfood-org count.
module "api_lb" {
  count = var.enable_api_lb ? 1 : 0

  source      = "./modules/api-lb"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  cloud_run_service = module.cloud_run.service_name
  api_apex          = var.api_host_suffix
  dns_zone_name     = var.enable_dns ? module.dns[0].zone_name : ""

  depends_on = [
    google_project_service.apis,
    module.cloud_run,
  ]
}

# --- Cloud Build ---
module "cloud_build" {
  source      = "./modules/cloud-build"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  repository_name = module.artifact_registry.repository_name

  cloud_build_sa_id = module.iam.cloud_build_sa_id
  cloud_run_service = module.cloud_run.service_name

  github_owner  = var.github_owner
  github_repo   = var.github_repo
  github_branch = var.github_branch

  depends_on = [
    module.artifact_registry,
    module.iam,
  ]
}

# --- Metrics exporter Cloud Run Job + Scheduler trigger ---
module "metrics_exporter_job" {
  source      = "./modules/metrics-exporter-job"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  service_account_email = module.iam.cloud_run_sa_email
  scheduler_sa_email    = module.iam.scheduler_sa_email

  image = "${var.region}-docker.pkg.dev/${var.project_id}/${module.artifact_registry.repository_name}/overslash-metrics-exporter:latest"

  cloud_sql_connection_name = module.cloud_sql.connection_name
  db_user                   = module.cloud_sql.db_user
  db_name                   = module.cloud_sql.db_name
  db_password_secret_id     = module.secret_manager.db_password_secret_id

  use_private_vpc  = var.use_private_vpc
  vpc_connector_id = var.use_private_vpc ? module.networking[0].vpc_connector_id : ""

  depends_on = [
    module.cloud_sql,
    module.secret_manager,
    module.artifact_registry,
    module.iam,
  ]
}

# --- Cloud Build trigger for the exporter image ---
module "cloud_build_metrics_exporter" {
  source      = "./modules/cloud-build-metrics-exporter"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  repository_name = module.artifact_registry.repository_name

  cloud_build_sa_id  = module.iam.cloud_build_sa_id
  cloud_run_job_name = module.metrics_exporter_job.job_name

  github_owner  = var.github_owner
  github_repo   = var.github_repo
  github_branch = var.github_branch

  depends_on = [
    module.artifact_registry,
    module.iam,
    module.metrics_exporter_job,
  ]
}

# --- Night shutdown scheduler (optional) ---
module "infra_scheduler" {
  count = var.enable_infra_scheduler ? 1 : 0

  source      = "./modules/infra-scheduler"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  cloud_sql_instance_name = module.cloud_sql.instance_name
  stop_cron               = var.infra_scheduler_stop_cron
  start_cron              = var.infra_scheduler_start_cron

  scheduler_sa_email = module.iam.scheduler_sa_email

  depends_on = [google_project_service.apis]
}

# --- DNS (optional) ---
module "dns" {
  count = var.enable_dns ? 1 : 0

  source      = "./modules/dns"
  base_prefix = local.base_prefix
  domain      = var.domain

  depends_on = [google_project_service.apis]
}

# --- Memorystore Redis (optional) ---
module "memorystore" {
  count = var.enable_valkey && var.use_private_vpc ? 1 : 0

  source      = "./modules/memorystore"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  memory_size_gb     = var.valkey_memory_size_gb
  authorized_network = module.networking[0].vpc_id

  depends_on = [google_project_service.apis]
}

# --- oversla.sh shortener Cloud Run service (optional) ---
# Requires `enable_valkey = true` + `use_private_vpc = true` so the service
# can reach private Memorystore via the Serverless VPC Access connector.
module "cloud_run_shortener" {
  count = var.enable_shortener ? 1 : 0

  source      = "./modules/cloud-run-shortener"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  service_account_email = module.iam.cloud_run_sa_email
  vpc_connector_id      = var.use_private_vpc ? module.networking[0].vpc_connector_id : ""

  image = "${var.region}-docker.pkg.dev/${var.project_id}/${module.artifact_registry.repository_name}/oversla-sh:latest"

  cpu           = var.shortener_cpu
  memory        = var.shortener_memory
  max_instances = var.shortener_max_instances

  api_key_secret_id = module.secret_manager.shortener_api_key_secret_id

  valkey_host = var.enable_valkey && var.use_private_vpc ? module.memorystore[0].redis_host : ""
  valkey_port = var.enable_valkey && var.use_private_vpc ? module.memorystore[0].redis_port : ""

  base_url          = var.shortener_base_url
  domain            = var.shortener_domain
  root_redirect_url = var.shortener_root_redirect_url

  depends_on = [
    module.memorystore,
    module.secret_manager,
    module.artifact_registry,
  ]
}

# --- overfwd Mailbox Gateway Cloud Run service (optional) ---
#
# The shared gateway behind `services/email.yaml`'s
# `servers: https://mailbox.overslash.com`. Deliberately NOT attached to the
# VPC — see the module for why. No Cloud Build trigger: this is a third-party
# image (overspiral/overfwd) pulled through the Docker Hub mirror at a pinned
# digest, not something this repo builds.
module "cloud_run_overfwd" {
  count = var.enable_overfwd ? 1 : 0

  source      = "./modules/cloud-run-overfwd"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  service_account_email = module.iam.cloud_run_sa_email

  image = "${module.artifact_registry.docker_hub_repository_url}/${var.overfwd_image}"

  cpu           = var.overfwd_cpu
  memory        = var.overfwd_memory
  min_instances = var.overfwd_min_instances
  max_instances = var.overfwd_max_instances
  concurrency   = var.overfwd_concurrency

  api_key_secret_id = module.secret_manager.overfwd_gateway_key_secret_id

  domain = var.overfwd_domain

  depends_on = [
    module.secret_manager,
    module.artifact_registry,
  ]
}

# --- Cloud Build trigger for the shortener image (optional) ---
module "cloud_build_shortener" {
  count = var.enable_shortener ? 1 : 0

  source      = "./modules/cloud-build-shortener"
  project_id  = var.project_id
  region      = var.region
  base_prefix = local.base_prefix

  repository_name = module.artifact_registry.repository_name

  cloud_build_sa_id = module.iam.cloud_build_sa_id
  cloud_run_service = module.cloud_run_shortener[0].service_name

  github_owner  = var.github_owner
  github_repo   = var.github_repo
  github_branch = var.github_branch

  depends_on = [
    module.artifact_registry,
    module.iam,
    module.cloud_run_shortener,
  ]
}
