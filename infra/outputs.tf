output "cloud_run_url" {
  description = "Cloud Run service URL"
  value       = module.cloud_run.service_url
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL instance connection name"
  value       = module.cloud_sql.connection_name
}

output "artifact_registry_url" {
  description = "Artifact Registry repository URL"
  value       = module.artifact_registry.repository_url
}

output "cloud_run_service_account" {
  description = "Cloud Run service account email"
  value       = module.iam.cloud_run_sa_email
}

output "cloud_build_service_account" {
  description = "Cloud Build service account email"
  value       = module.iam.cloud_build_sa_email
}

output "redis_host" {
  description = "Redis host (if enabled)"
  value       = var.enable_redis ? module.memorystore[0].redis_host : ""
}
