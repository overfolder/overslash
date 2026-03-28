output "cloud_run_url" {
  value = google_cloud_run_v2_service.overslash.uri
}

output "cloud_sql_connection_name" {
  value = google_sql_database_instance.postgres.connection_name
}

output "cloud_sql_private_ip" {
  value = google_sql_database_instance.postgres.private_ip_address
}

output "artifact_registry_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.overslash.repository_id}"
}

output "service_account_email" {
  value = google_service_account.cloud_run.email
}
