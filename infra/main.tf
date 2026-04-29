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

  depends_on = [google_project_service.apis]
}

# --- Secret Manager ---
module "secret_manager" {
  source      = "./modules/secret-manager"
  project_id  = var.project_id
  base_prefix = local.base_prefix

  cloud_run_sa_email = module.iam.cloud_run_sa_email

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
  google_services_client_id_secret_id     = module.secret_manager.google_services_client_id_secret_id
  google_services_client_secret_secret_id = module.secret_manager.google_services_client_secret_secret_id

  # Billing
  cloud_billing                   = var.cloud_billing
  stripe_eur_lookup_key           = var.stripe_eur_lookup_key
  stripe_usd_lookup_key           = var.stripe_usd_lookup_key
  stripe_secret_key_secret_id     = module.secret_manager.stripe_secret_key_secret_id
  stripe_webhook_secret_secret_id = module.secret_manager.stripe_webhook_secret_secret_id

  db_user = module.cloud_sql.db_user
  db_name = module.cloud_sql.db_name

  domain           = var.domain
  dashboard_origin = var.dashboard_origin
  dashboard_url    = var.dashboard_url
  enable_dev_auth  = var.enable_dev_auth

  redis_host = var.enable_valkey && var.use_private_vpc ? module.memorystore[0].redis_host : ""
  redis_port = var.enable_valkey && var.use_private_vpc ? module.memorystore[0].redis_port : ""

  enable_metrics_sidecar = var.enable_metrics_sidecar

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

  alert_email               = var.alert_email
  pagerduty_integration_key = var.pagerduty_integration_key
  api_domain                = var.domain
  api_service_name          = module.cloud_run.service_name
  cloud_sql_instance_name   = module.cloud_sql.instance_name
  monthly_budget_usd        = var.monthly_budget_usd
  billing_account_id        = var.billing_account_id

  depends_on = [
    google_project_service.apis,
    module.cloud_run,
    module.cloud_sql,
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
