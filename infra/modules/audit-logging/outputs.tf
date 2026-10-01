output "bucket_id" {
  value = google_logging_project_bucket_config.audit.bucket_id
}

output "bucket_locked" {
  value = google_logging_project_bucket_config.audit.locked
}

output "sink_name" {
  value = google_logging_project_sink.audit.name
}

output "unexpected_secret_access_metric" {
  value = google_logging_metric.unexpected_secret_access.name
}
