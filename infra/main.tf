provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

module "overslash" {
  source = "./modules/project"

  project_id              = var.project_id
  region                  = var.region
  environment             = var.environment
  domain                  = var.domain
  cloud_run_min_instances = var.cloud_run_min_instances
  cloud_run_max_instances = var.cloud_run_max_instances
  cloud_sql_tier          = var.cloud_sql_tier
  cloud_sql_disk_size_gb  = var.cloud_sql_disk_size_gb
  docker_image            = var.docker_image
}
