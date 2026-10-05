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

Overslash uses **two separate Google OAuth clients** — one for user sign-in,
one for connecting Google services on behalf of users. Register them in two
separate GCP projects so the sensitive-scope verification applies only to the
services client, leaving sign-in unaffected by verification delays.

**Login client** (Sign-in with Google, `openid email profile` — no verification needed):

Authorized redirect URI: `https://<your-host>/auth/callback/google`

```bash
echo -n "your-login-client-id"     | gcloud secrets versions add overslash-prod-oauth-client-id     --data-file=-
echo -n "your-login-client-secret" | gcloud secrets versions add overslash-prod-oauth-client-secret --data-file=-
```

**Services client** (Calendar/Drive/Gmail, sensitive scopes — requires Google verification):

Authorized redirect URI: `https://<your-host>/v1/oauth/callback`

```bash
echo -n "your-services-client-id"     | gcloud secrets versions add overslash-prod-google-services-client-id     --data-file=-
echo -n "your-services-client-secret" | gcloud secrets versions add overslash-prod-google-services-client-secret --data-file=-
```

Cloud Run reads the services client as `OAUTH_GOOGLE_CLIENT_ID/_SECRET` via
the env-var tier of the OAuth cascade (`OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1`
is set by Terraform). Any org can override with its own client by calling
`POST /v1/org/oauth-credentials/google` from the dashboard.

**GitHub login client** (Sign-in with GitHub, `read:user user:email`):

Register an **OAuth App** (not a GitHub App — the login flow relies on the
`read:user` / `user:email` scopes, which GitHub Apps ignore) under the
`overfolder` org, one per environment for secret isolation. Gated by
`enable_github_login` (on in dev/prod tfvars).

Authorized callback URL: `https://<your-host>/auth/callback/github`

```bash
echo -n "your-github-client-id"     | gcloud secrets versions add overslash-prod-github-auth-client-id     --data-file=-
echo -n "your-github-client-secret" | gcloud secrets versions add overslash-prod-github-auth-client-secret --data-file=-
```

Cloud Run reads these as `GITHUB_AUTH_CLIENT_ID/_SECRET`; the API advertises
the GitHub button on `/auth/providers` only once both are populated.

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
| `artifact-registry` | Docker image repository with cleanup policy (+ optional Docker Hub pull-through mirror) |
| `secret-manager` | DB password, encryption key, Google + GitHub login + Google services OAuth secrets |
| `cloud-sql` | PostgreSQL 16 (Auth Proxy or private IP mode). TLS-only, deletion-protected, pgAudit on — see [docs/runbooks/cloud-sql-hardening.md](../docs/runbooks/cloud-sql-hardening.md) |
| `cloud-run` | Overslash API with health checks and secret injection |
| `cloud-build` | GitHub push trigger: build -> push -> deploy |
| `infra-scheduler` | (Optional) Stop/start Cloud SQL on cron (Europe/Madrid) |
| `dns` | (Optional) Cloud DNS managed zone |
| `memorystore` | (Optional) Valkey via Memorystore |
| `cloud-run-shortener` | (Optional) oversla.sh URL shortener |
| `cloud-run-overfwd` | (Optional) Shared overfwd Mailbox Gateway behind `services/email.yaml` — see [docs/runbooks/mailbox-gateway.md](../docs/runbooks/mailbox-gateway.md) |
| `audit-logging` | Data Access audit logs, a retained (and in prod **locked**) audit log bucket + sink, and an alert on unexpected secret reads — see [Audit logging](#audit-logging-casa-671) |

### Mailbox Gateway (overfwd)

`enable_overfwd = true` deploys the shared gateway that `services/email.yaml`
points at, plus the GSM secret both it and the API read, plus the Docker Hub
mirror its (digest-pinned, third-party) image is pulled through. Two manual
steps per environment: a `mailbox[.dev] CNAME ghs.googlehosted.com` at the
registrar, and Search Console verification of the apex. Full operating notes —
key rotation, image upgrades, smoke tests — are in
[docs/runbooks/mailbox-gateway.md](../docs/runbooks/mailbox-gateway.md).

### Client IP & trusted proxies

Every audit row's `ip_address` and every per-IP throttle (magic-link request,
uploads, downloads) read the `ClientIp` extractor, which resolves the client
right to left: it walks `X-Forwarded-For` from the socket peer leftwards and
takes the first address it has no reason to trust. Anything left of that was
written by the caller and is ignored. With nothing configured, the header is
ignored entirely and the socket peer is the client. Code and decision table:
`crates/overslash-api/src/services/client_ip.rs`.

| Variable | tfvar | Meaning |
|---|---|---|
| `OVERSLASH_TRUSTED_PROXY_HOPS` | `trusted_proxy_hops` | Addresses, counting the socket peer, trusted by position |
| `OVERSLASH_TRUSTED_PROXIES` | `trusted_proxy_cidrs` | CIDRs (or bare IPs) trusted wherever they appear |
| `OVERSLASH_TRUSTED_PROXY_SECRET` | `enable_trusted_proxy_secret` + GSM `overslash-<env>-trusted-proxy-secret` | A request carrying it in `x-overslash-proxy-secret` has its client taken from `x-overslash-client-ip` in place of the proxy hop |

A malformed value refuses the boot.

What each path looks like at the container, and what gets recorded:

| Path | `X-Forwarded-For` (peer = Google frontend) | Recorded |
|---|---|---|
| Agent → `api.dev.overslash.com` / `*.run.app` (dev) | `<spoof…>, <client>` | `<client>` (hop 1) |
| Agent → `api.overslash.com` (GCLB, prod) | `<spoof…>, <client>, 34.36.8.174, <google-egress>` | `<client>` (egress = hop 2, LB by CIDR) |
| Browser → `app.*` → Vercel rewrite → API | `<client>, <vercel-egress>[, <lb>, <google-egress>]` | `<client>` with the secret, `<vercel-egress>` without |

| Env | `trusted_proxy_hops` | `trusted_proxy_cidrs` | Cloud Run ingress |
|---|---|---|---|
| prod | `2` | `34.36.8.174/32` (the LB address) | LB only (`INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`) |
| dev | `1` | `""` (no LB) | all |

**The LB's egress hop.** Behind the global external Application Load Balancer
(serverless NEG), the LB appends `<client>, <lb-ip>`, and then the hop into Cloud
Run appends one more Google address. That address comes from a range Google
doesn't publish (34.96.62.132 in practice) and isn't one of the documented
35.191.0.0/16 / 130.211.0.0/22 LB ranges, so it can't be trusted by CIDR. While
prod ran with `hops = 1`, every agent and MCP call recorded it. Prod therefore
trusts two hops by position. That is safe **only** because `enable_api_lb` also
restricts the service's ingress to the LB (`infra/main.tf`). If `*.run.app`
were reachable, Cloud Run would append a direct caller's real address in the
trusted second slot, and the caller's forged entry to its left would be
recorded. See D102 and the decision that amends it.

The prod LB address is a literal because `module.api_lb` depends on
`module.cloud_run`. If `tofu output` ever shows a different `lb_ip`, update
`prod.tfvars`. Nothing here is applied by CI. Run `make tofu-plan ENV=prod`
before trusting that the live env matches these files:
`OVERSLASH_TRUSTED_PROXIES` sat in `prod.tfvars` for a week without ever
reaching Cloud Run.

**The Vercel hop.** Vercel connects to the API from egress IPs it does not
publish, so its address can't be trusted by range. And the `X-Forwarded-For`
it sends upstream on an external rewrite is **not** its own observation: it
forwards the browser's header and does not reliably apply a middleware
override of it (measured on dev). So `dashboard/middleware.ts`, on every path
`vercel.json` rewrites to the API, stamps two headers of its own:
`x-overslash-proxy-secret` (the value of `OVERSLASH_TRUSTED_PROXY_SECRET`, the
same variable name the API reads) and `x-overslash-client-ip` (the address
Vercel saw, `x-real-ip`). Both are set, never passed through. Without an
address or the variable, both are stripped. On a secret match the API takes
the client from `x-overslash-client-ip` and never reads XFF further left.
Enabling it, per env:

```bash
SECRET=$(openssl rand -hex 32)
printf %s "$SECRET" | gcloud secrets versions add overslash-<env>-trusted-proxy-secret --data-file=- --project <project>
vercel env add OVERSLASH_TRUSTED_PROXY_SECRET production   # prod value; `preview` for dev
# prod/dev.tfvars: enable_trusted_proxy_secret = true, then make tofu-apply ENV=<env>
```

Either order is safe. Until both halves hold the same value, dashboard traffic
records the Vercel egress address. To rotate, repeat the steps with a new
value. Dashboard requests record the egress address in the window between the
two updates.

**Verifying after a deploy.** `curl -si https://app.overslash.com/health | grep
x-overslash-proxy-mw` should print `1` (the middleware ran and had a secret).
Then make an audited call directly with a forged header, e.g.
`curl -X PUT -H 'X-Forwarded-For: 203.0.113.9' -H "Authorization: Bearer $KEY" …/v1/secrets/probe -d '{"value":"x"}'`.
The `secret.put` row in `/v1/audit` must show your own address, not
`203.0.113.9`. Do the same from the dashboard: the row should show your
browser's address, not a Vercel or Google one.

### Audit logging (CASA 6.7.1)

`module.audit_logging` turns on Data Access audit logs (`ADMIN_READ`, `DATA_READ`,
`DATA_WRITE`) for Secret Manager, Cloud SQL (`cloudsql.googleapis.com`, which also carries pgAudit output) and Cloud Run; routes every Cloud
Audit Log into a dedicated bucket `overslash-<env>-audit` kept for
`audit_log_retention_days` (400); and alerts (P1, email) whenever a principal other than
the runtime service account reads a secret payload. Policy and rationale:
[docs/compliance/casa/secrets-access-policy.md](../docs/compliance/casa/secrets-access-policy.md).

> **`audit_log_bucket_locked = true` is IRREVERSIBLE.** It is `true` in
> `env/prod.tfvars` only. The apply that carries it locks `overslash-prod-audit`
> forever: its retention can never be changed (not raised, not lowered), it cannot be
> deleted until its last entry ages out, the lock cannot be lifted, and `tofu destroy`
> on prod fails at that resource. Review the plan line `locked = true` /
> `retention_days = 400` before typing `prod`.

The unexpected-secret-access alert **fires on your own `tofu plan`**: the provider reads
every `google_secret_manager_secret_version` on refresh, and prod reads the PagerDuty key
as a data source. That is intended — human reads of platform secrets are meant to be seen.
Expect one email per plan, naming you.

**Applying it.** Dev first, then prod, and prod in two steps so the lock lands only on a
bucket you have already watched fill:

```bash
# 1. Dev (unlocked).
make tofu-plan ENV=dev          # expect the 8 audit-logging adds, 0 to change, 0 to destroy (plus any unrelated drift)
make tofu-apply ENV=dev

# 2. Verify on dev: Data Access on, sink writing, and a secret read shows up.
gcloud projects get-iam-policy overslash-dev --format=json | jq .auditConfigs
gcloud secrets versions access latest --secret=overslash-dev-pagerduty-integration-key --project=overslash-dev >/dev/null
#    within ~2 min: the entry below, and a "[P1] overslash-dev Unexpected Secret Access" email naming you
gcloud logging read 'protoPayload.methodName:"AccessSecretVersion"' --project=overslash-dev \
  --bucket=overslash-dev-audit --location=europe-west1 --view=_AllLogs --limit=3 --freshness=1h

# 3. Leave dev for a few days and read the real volume before prod:
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Fdata_access"' --project=overslash-dev \
  --freshness=1d --format=json | wc -c

# 4. Prod, UNLOCKED first. A command-line -var beats -var-file, so this one plan
#    overrides prod.tfvars (TF_VAR_* would not — tfvars wins over the environment).
cd infra && tofu workspace select prod && \
  tofu plan -var-file=env/prod.tfvars -var audit_log_bucket_locked=false -out=prod.tfplan && cd ..
#    expect the 8 audit-logging adds; the bucket shows locked = false
make tofu-apply ENV=prod
#    repeat the step-2 checks against overslash / overslash-prod-audit

# 5. Prod, LOCK. Irreversible. The plan must show exactly one in-place update:
#    module.audit_logging.google_logging_project_bucket_config.audit  locked: false -> true
make tofu-plan ENV=prod
make tofu-apply ENV=prod
gcloud logging buckets describe overslash-prod-audit --location=europe-west1 --project=overslash
#    expect: locked: true, retentionDays: 400
```

Reading Data Access entries needs `roles/logging.privateLogViewer` (Owners have it).

If the first apply fails on the alert policy with `Cannot find metric(s) that match type
= "logging.googleapis.com/user/…"`, the just-created log-based metric has not
propagated yet: re-plan and apply again after a minute.

**Cost.** Measured 2026-09-28: `overslash` ingests ~0.2 GiB of billable logs per 30 days
and writes ~960 Admin Activity / System Event entries a day (~5 KiB each). Data Access
adds, by estimate, 1,500–3,000 entries a day — dominated by the metrics-exporter job
(every 5 min: a DB-password read plus Cloud SQL connector calls) and Cloud Run instance
starts (one read per mounted secret) — so ~0.3–0.5 GiB/month, counted twice (the
`_Default` copy and the audit bucket). That is ~1–1.5 GiB/month against Cloud Logging's
50 GiB/project free ingestion allotment: **$0 ingestion**. Retention past 30 days bills at
$0.01/GiB-month; at steady state (400 days, ~8 GiB held) that is **~$0.10/month**. The
alert policy is one condition (~$0.10/month); the log-based metric is near-empty. Total
**under $1/month per project**. Step 3 exists to replace this estimate with a measurement
before the prod bucket is locked.

## Connectivity Modes

- **Auth Proxy (default, `use_private_vpc = false`)**: Cloud SQL has public IP but only accepts Auth Proxy connections (IAM-authenticated). No VPC connector needed. Saves ~$7/month.
- **Private VPC (`use_private_vpc = true`)**: Full VPC with private IP. Cloud SQL has no public IP. Requires VPC Access connector.

## Cost Estimate (minimum, idle)

| Resource | Monthly |
|----------|---------|
| Cloud SQL db-f1-micro + 10GB | ~$9 |
| Cloud Run (scale to zero) | ~$0 |
| Secret Manager (6 secrets) | ~$0.09 |
| Artifact Registry | ~$0.10/GB |
| Audit logging (Data Access + 400-day bucket + alert) | < $1 |
| Cloud Scheduler (2 jobs) | ~$0 |
| **Total** | **~$9-10/month** |

With `enable_infra_scheduler = true`, Cloud SQL is stopped during Spanish nights, reducing the DB cost by ~30%.
