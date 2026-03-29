# Overslash Infrastructure

OpenTofu (Terraform-compatible) configuration to deploy Overslash to Google Cloud Run with all GCP dependencies.

## Architecture

```
Internet → Cloud Run (overslash-api)
               ├── Cloud SQL (PostgreSQL 16, private IP)
               ├── Secret Manager (DB password, encryption key, OAuth secrets)
               └── Memorystore Redis (optional, for webhooks/pub-sub)

Cloud Build → Artifact Registry → Cloud Run (auto-deploy on push to master)
```

## Prerequisites

1. [OpenTofu](https://opentofu.org/docs/intro/install/) >= 1.6.0
2. [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) (`gcloud`)
3. A GCP project with billing enabled
4. GitHub repository connected to Cloud Build (for CI/CD trigger)

## Quick Start

### 1. Authenticate

```bash
gcloud auth login
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
```

### 2. Configure

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your project ID and preferences
```

### 3. Initialize and Deploy

```bash
tofu init
tofu plan
tofu apply
```

### 4. First Deploy — Push the Docker Image

After infrastructure is created, you need to push the first Docker image. Cloud Build will handle this automatically on the next push to `master`. To trigger manually:

```bash
# Build and push from your machine
IMAGE_URL=$(tofu output -raw artifact_registry_url)/overslash-api:latest
gcloud auth configure-docker europe-west1-docker.pkg.dev
docker build -t $IMAGE_URL ..
docker push $IMAGE_URL

# Deploy to Cloud Run
gcloud run deploy overslash-api \
  --image $IMAGE_URL \
  --region europe-west1
```

### 5. Set OAuth Secrets

The initial deploy creates placeholder values for OAuth secrets. Update them:

```bash
echo -n "your-client-id" | gcloud secrets versions add overslash-oauth-client-id --data-file=-
echo -n "your-client-secret" | gcloud secrets versions add overslash-oauth-client-secret --data-file=-
```

## Modules

| Module | Purpose |
|--------|---------|
| `networking` | VPC, subnet, private service access, VPC connector |
| `iam` | Service accounts for Cloud Run and Cloud Build (least-privilege) |
| `artifact-registry` | Docker image repository with cleanup policy |
| `secret-manager` | DB password, encryption key, OAuth secrets |
| `cloud-sql` | PostgreSQL 16, private networking, automated backups |
| `cloud-run` | Overslash API service with secret injection and health checks |
| `cloud-build` | CI/CD trigger: build → push → deploy on git push |
| `dns` | (Optional) Cloud DNS managed zone |
| `memorystore` | (Optional) Redis for webhooks/pub-sub |

## Variables

See `variables.tf` for all configurable options. Key ones:

| Variable | Default | Description |
|----------|---------|-------------|
| `project_id` | (required) | GCP project ID |
| `region` | `europe-west1` | GCP region |
| `domain` | `""` | Custom domain (empty = use Cloud Run URL) |
| `cloud_sql_tier` | `db-f1-micro` | Cloud SQL machine type |
| `enable_redis` | `false` | Enable Memorystore Redis |
| `enable_dns` | `false` | Enable Cloud DNS zone |

## Database Migrations

Migrations run automatically when the Overslash API starts (via sqlx). On first deploy, the database will be initialized with the full schema.

## Destroy

```bash
# Cloud SQL has deletion protection enabled by default.
# To destroy, first disable it:
tofu apply -var="..." -target=module.cloud_sql  # (after setting deletion_protection = false)
tofu destroy
```

## Cost Estimate

With default settings (minimum viable):
- Cloud Run: ~$0 (scale to zero, pay per request)
- Cloud SQL (db-f1-micro): ~$8/month
- Secret Manager: ~$0.06/month (4 secrets)
- Artifact Registry: ~$0.10/GB/month
- VPC Connector: ~$7/month (min 2 instances)
- **Total: ~$15-20/month** (idle, no Redis)
