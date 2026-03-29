# Enable required GCP APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "vpcaccess.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "redis.googleapis.com",
  ])

  service            = each.key
  disable_on_destroy = false
}

# --- Networking ---
module "networking" {
  source     = "./modules/networking"
  project_id = var.project_id
  region     = var.region

  depends_on = [google_project_service.apis]
}

# --- IAM ---
module "iam" {
  source     = "./modules/iam"
  project_id = var.project_id
  region     = var.region

  depends_on = [google_project_service.apis]
}

# --- Artifact Registry ---
module "artifact_registry" {
  source     = "./modules/artifact-registry"
  project_id = var.project_id
  region     = var.region

  cloud_build_sa_email = module.iam.cloud_build_sa_email

  depends_on = [google_project_service.apis]
}

# --- Secret Manager ---
module "secret_manager" {
  source     = "./modules/secret-manager"
  project_id = var.project_id

  cloud_run_sa_email = module.iam.cloud_run_sa_email

  depends_on = [google_project_service.apis]
}

# --- Cloud SQL ---
module "cloud_sql" {
  source     = "./modules/cloud-sql"
  project_id = var.project_id
  region     = var.region

  tier         = var.cloud_sql_tier
  disk_size_gb = var.cloud_sql_disk_size_gb
  zone         = var.cloud_sql_zone

  private_network_id = module.networking.vpc_id

  db_password_secret_id = module.secret_manager.db_password_secret_id

  depends_on = [
    google_project_service.apis,
    module.networking,
  ]
}

# --- Cloud Run ---
module "cloud_run" {
  source     = "./modules/cloud-run"
  project_id = var.project_id
  region     = var.region

  service_account_email = module.iam.cloud_run_sa_email
  vpc_connector_id      = module.networking.vpc_connector_id

  image = "${var.region}-docker.pkg.dev/${var.project_id}/${module.artifact_registry.repository_name}/overslash-api:latest"

  cpu           = var.cloud_run_cpu
  memory        = var.cloud_run_memory
  min_instances = var.cloud_run_min_instances
  max_instances = var.cloud_run_max_instances

  cloud_sql_connection_name = module.cloud_sql.connection_name

  # Secret references
  db_password_secret_id         = module.secret_manager.db_password_secret_id
  encryption_key_secret_id      = module.secret_manager.encryption_key_secret_id
  oauth_client_id_secret_id     = module.secret_manager.oauth_client_id_secret_id
  oauth_client_secret_secret_id = module.secret_manager.oauth_client_secret_secret_id

  db_user = module.cloud_sql.db_user
  db_name = module.cloud_sql.db_name

  domain = var.domain

  redis_host = var.enable_redis ? module.memorystore[0].redis_host : ""
  redis_port = var.enable_redis ? module.memorystore[0].redis_port : ""

  depends_on = [
    module.cloud_sql,
    module.secret_manager,
    module.networking,
    module.artifact_registry,
  ]
}

# --- Cloud Build ---
module "cloud_build" {
  source     = "./modules/cloud-build"
  project_id = var.project_id
  region     = var.region

  repository_id   = module.artifact_registry.repository_id
  repository_name = module.artifact_registry.repository_name

  cloud_build_sa_id = module.iam.cloud_build_sa_id
  cloud_run_service = "overslash-api"

  github_owner  = var.github_owner
  github_repo   = var.github_repo
  github_branch = var.github_branch

  depends_on = [
    module.artifact_registry,
    module.iam,
  ]
}

# --- DNS (optional) ---
module "dns" {
  count = var.enable_dns ? 1 : 0

  source = "./modules/dns"
  domain = var.domain
}

# --- Memorystore Redis (optional) ---
module "memorystore" {
  count = var.enable_redis ? 1 : 0

  source     = "./modules/memorystore"
  project_id = var.project_id
  region     = var.region

  memory_size_gb     = var.redis_memory_size_gb
  authorized_network = module.networking.vpc_id

  depends_on = [
    google_project_service.apis,
    module.networking,
  ]
}
