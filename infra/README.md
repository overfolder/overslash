# Overslash Infrastructure

OpenTofu (Terraform-compatible) configuration to deploy Overslash to Google Cloud Run with all GCP dependencies.

## Architecture

```
Internet -> Cloud Run (overslash-{env}-api)
                |-- Cloud SQL Auth Proxy -> Cloud SQL (overslash-{env}-db)
                |-- Secret Manager (overslash-{env}-*)
                '-- Memorystore Valkey (optional, overslash-{env}-valkey)

Cloud Build (overslash-{env}-deploy) -> Artifact Registry -> Cloud Run
Cloud Scheduler (optional) -> stops/starts Cloud SQL on cron
```

## Naming Convention

All resources follow: `overslash-{env}-{component}`

Where `env` defaults to the tofu workspace name (overridable via `var.env`).

## Prerequisites

1. [OpenTofu](https://opentofu.org/docs/intro/install/) >= 1.6.0
2. [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) (`gcloud`)
3. A GCP project with billing enabled
4. GitHub repository connected to Cloud Build

## Quick Start

### 1. Authenticate

```bash
gcloud auth login
gcloud auth application-default login
```

### 2. Deploy

```bash
# Dev (project: overslash-dev)
make tofu-plan ENV=dev
make tofu-apply ENV=dev

# Prod (project: overslash, requires confirmation)
make tofu-plan ENV=prod
make tofu-apply ENV=prod
```

### 3. First Docker Image Push

```bash
IMAGE_URL=$(tofu output -raw artifact_registry_url)/overslash-api:latest
gcloud auth configure-docker europe-west1-docker.pkg.dev
docker build -t $IMAGE_URL ..
docker push $IMAGE_URL
```

### 4. Set OAuth Secrets

```bash
echo -n "your-client-id" | gcloud secrets versions add overslash-prod-oauth-client-id --data-file=-
echo -n "your-client-secret" | gcloud secrets versions add overslash-prod-oauth-client-secret --data-file=-
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make tofu-init` | Initialize providers |
| `make tofu-fmt` | Check formatting |
| `make tofu-validate` | Validate configuration |
| `make tofu-plan ENV=prod` | Plan changes (saves to `prod.tfplan`) |
| `make tofu-apply ENV=prod` | Apply saved plan (prod requires confirmation) |
| `make tofu-destroy ENV=prod` | Destroy all resources |
| `make infra-shutdown ENV=prod` | Manually stop Cloud SQL |
| `make infra-resume ENV=prod` | Manually start Cloud SQL |

## Modules

| Module | Purpose |
|--------|---------|
| `networking` | VPC + private service access (only when `use_private_vpc = true`) |
| `iam` | Least-privilege SAs for Cloud Run, Cloud Build, Cloud Scheduler |
| `artifact-registry` | Docker image repository with cleanup policy |
| `secret-manager` | DB password, encryption key, OAuth secrets |
| `cloud-sql` | PostgreSQL 16 (Auth Proxy or private IP mode) |
| `cloud-run` | Overslash API with health checks and secret injection |
| `cloud-build` | GitHub push trigger: build -> push -> deploy |
| `infra-scheduler` | (Optional) Stop/start Cloud SQL on cron (Europe/Madrid) |
| `dns` | (Optional) Cloud DNS managed zone |
| `memorystore` | (Optional) Valkey via Memorystore |

## Connectivity Modes

- **Auth Proxy (default, `use_private_vpc = false`)**: Cloud SQL has public IP but only accepts Auth Proxy connections (IAM-authenticated). No VPC connector needed. Saves ~$7/month.
- **Private VPC (`use_private_vpc = true`)**: Full VPC with private IP. Cloud SQL has no public IP. Requires VPC Access connector.

## Cost Estimate (minimum, idle)

| Resource | Monthly |
|----------|---------|
| Cloud SQL db-f1-micro + 10GB | ~$9 |
| Cloud Run (scale to zero) | ~$0 |
| Secret Manager (4 secrets) | ~$0.06 |
| Artifact Registry | ~$0.10/GB |
| Cloud Scheduler (2 jobs) | ~$0 |
| **Total** | **~$9-10/month** |

With `enable_infra_scheduler = true`, Cloud SQL is stopped during Spanish nights, reducing the DB cost by ~30%.
