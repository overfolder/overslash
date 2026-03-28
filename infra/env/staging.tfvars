project_id              = "overslash-prod"
environment             = "staging"
region                  = "us-central1"
cloud_run_min_instances = 1
cloud_run_max_instances = 3
cloud_sql_tier          = "db-f1-micro"
cloud_sql_disk_size_gb  = 10
docker_image            = "us-central1-docker.pkg.dev/overslash-prod/overslash/overslash-api:latest"
