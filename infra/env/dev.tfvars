project_id  = "overslash-dev"
region      = "europe-west1"
environment = "dev"

domain = ""

cloud_sql_tier         = "db-f1-micro"
cloud_sql_disk_size_gb = 10

cloud_run_cpu           = "1"
cloud_run_memory        = "512Mi"
cloud_run_min_instances = 0
cloud_run_max_instances = 3

github_owner  = "overfolder"
github_repo   = "overslash"
github_branch = "^dev$"

enable_redis = false
enable_dns   = false
