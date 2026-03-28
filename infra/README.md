# Overslash Infrastructure

GCP infrastructure managed by OpenTofu.

## Architecture

```
Internet -> Cloud Run (min-instances=1) -> Cloud SQL PostgreSQL 16 (private IP)
                                        -> Secret Manager (DATABASE_URL, ENCRYPTION_KEY)
```

## Prerequisites

- [OpenTofu](https://opentofu.org/) >= 1.8
- `gcloud` CLI authenticated (`gcloud auth application-default login`)
- GCP project created

## Bootstrap (one-time)

```bash
export PROJECT_ID=overslash-prod
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  compute.googleapis.com \
  servicenetworking.googleapis.com

# Create state bucket
gsutil mb -l us-central1 gs://overslash-tofu-state
gsutil versioning set on gs://overslash-tofu-state
```

## Usage

```bash
cd infra

# Initialize
tofu init

# Plan
tofu plan -var-file=env/prod.tfvars

# Apply
tofu apply -var-file=env/prod.tfvars
```

## Environments

| File | Purpose |
|------|---------|
| `env/dev.tfvars` | Development (scale-to-zero, micro DB) |
| `env/staging.tfvars` | Staging (min 1 instance, micro DB) |
| `env/prod.tfvars` | Production (min 1 instance, custom DB, custom domain) |

## Workload Identity Federation (GitHub Actions)

Set up WIF so GitHub Actions can deploy without service account keys:

```bash
# Create workload identity pool
gcloud iam workload-identity-pools create github-pool \
  --location=global \
  --display-name="GitHub Actions Pool"

# Create OIDC provider
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location=global \
  --workload-identity-pool=github-pool \
  --display-name="GitHub" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"

# Create deploy service account
gcloud iam service-accounts create overslash-deploy \
  --display-name="Overslash Deploy (GitHub Actions)"

# Grant permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:overslash-deploy@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:overslash-deploy@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.developer"

# Allow deploy SA to act as the Cloud Run runtime SA
gcloud iam service-accounts add-iam-policy-binding \
  overslash-prod-run@${PROJECT_ID}.iam.gserviceaccount.com \
  --member="serviceAccount:overslash-deploy@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser"

# Bind GitHub repo to deploy SA (replace YOUR_ORG and PROJECT_NUMBER)
gcloud iam service-accounts add-iam-policy-binding \
  overslash-deploy@${PROJECT_ID}.iam.gserviceaccount.com \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/attribute.repository/YOUR_ORG/overslash" \
  --role="roles/iam.workloadIdentityUser"
```

Then set GitHub repository secrets:
- `WIF_PROVIDER`: `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider`
- `WIF_SERVICE_ACCOUNT`: `overslash-deploy@PROJECT_ID.iam.gserviceaccount.com`
