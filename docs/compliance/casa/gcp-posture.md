# GCP posture — live scan

What Google's own Recommender and the live project configuration say, as opposed to what
the Terraform says. Complements [gap-assessment.md](gap-assessment.md), which was written
from the IaC.

**Both environments measured** — `overslash` (production) and `overslash-dev` — on
2026-09-22, read-only, via `roles/viewer`. Nothing here is inferred any more.

Re-run before each revalidation. Recommender output is generated from a rolling
observation window, so an empty result on a quiet project is not the same as a clean one —
and check for an *error* rather than trusting an empty list, which is how the first pass of
this scan briefly mis-read production as having no findings.

---

## Google Recommender — production

### Cloud SQL Security (`google.cloudsql.instance.SecurityRecommender`, `europe-west1`)

Four on `overslash-prod-db`. The paired `SecurityInsight` severities are Google's own
rating of the underlying observation:

| Recommendation | Insight severity | Finding | CASA |
|---|---|---|---|
| **P2** `REQUIRE_SSL` | **HIGH** `SSL_NOT_REQUIRED` | "This instance is not enforcing SSL encryption requirements for direct connections." | **4.1.1** |
| P3 `ENABLE_INSTANCE_PASSWORD_POLICY` | MEDIUM | No password policy for built-in authentication users | 1.1.1 |
| P3 `ENABLE_USER_PASSWORD_POLICY` | MEDIUM | No password expiry, no lockout on consecutive failures | 1.1.1 |
| P4 `ENABLE_DATABASE_AUDITING` | LOW | No record of which database user ran what | 6.7.1 |

Identical four on `overslash-dev-db`.

### IAM policy (`google.iam.policy.Recommender`, `global`)

Two P2 recommendations on production:

| Member | Role | Permissions used in 90 days | Recommended |
|---|---|---|---|
| `212015650448-compute@developer.gserviceaccount.com` — **the default Compute Engine service account** | `roles/editor` | **0** | remove the binding |
| `212015650448@cloudservices.gserviceaccount.com` — the Google APIs service agent | `roles/editor` | 12 | downgrade to `roles/compute.editor` |

For contrast, the third insight on the project is `user:amanuelmartincanto@gmail.com` at
`roles/owner` with 198 permissions used — a real, exercised binding.

Dev carries the same default-Compute-SA finding.

**This is the class of finding that reading the repo cannot produce.** The IaC audit
correctly reported "no `roles/editor` in code" — true, `infra/modules/iam/main.tf` grants
nothing of the sort. Both bindings are project-creation defaults, invisible to Terraform,
and there is no `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` to stop them
being recreated.

---

## Measured configuration

### Cloud SQL

| Setting | **`overslash-prod-db`** | `overslash-dev-db` | Terraform | CASA |
|---|---|---|---|---|
| `sslMode` | **`ALLOW_UNENCRYPTED_AND_ENCRYPTED`** | same | unset (`infra/modules/cloud-sql/main.tf:61-67`) | **4.1.1** |
| `requireSsl` | `false` | `false` | unset | **4.1.1** |
| `ipv4Enabled` | **`false`** — private IP on `overslash-prod-vpc` | `true`, public IP, **no authorized networks** | `!use_private_vpc` | 6.2.1 |
| `deletionProtectionEnabled` | **`false`** | `false` | `:49` | — |
| `availabilityType` | `ZONAL` | `ZONAL` | `:55` | — |
| `tier` | `db-f1-micro` | `db-f1-micro` | tfvars | — |
| `databaseFlags` | `max_connections=100` only | same | `:80-83` | 6.7.1 |
| Backups / PITR | enabled, 7 retained, PITR on, 7-day transaction logs | same | `:69-78` | — |

Production is correctly private — that half of the dev/prod difference holds. What does
**not** hold is the SSL posture: `sslMode` is unset in the shared module, so production
accepts unencrypted connections too, and that is what Google rates **HIGH**.

`deletionProtectionEnabled: false` **on the production database** is confirmed live.

On the dev public IP, read it precisely: a public IP with *zero* authorized networks is not
an open database, because GCP denies direct connections when the allowlist is empty. The
finding is the permissive `sslMode` and the existence of the surface — one
`authorizedNetworks` entry away from reachable, with no `constraints/sql.restrictPublicIp`
to prevent that.

### Memorystore — previously unverified anywhere

Memorystore only exists where `use_private_vpc` is true, so it has no dev counterpart and
the `gap-assessment.md` 6.7.1 finding rested on the module alone. Now measured:

| Instance | Tier | `authEnabled` | `transitEncryptionMode` | Persistence |
|---|---|---|---|---|
| `overslash-prod-valkey` | `BASIC` | **unset** | **`DISABLED`** | `DISABLED` |

**Confirmed: no AUTH and no in-transit encryption**, on the cache that `.env.example:20-30`
describes as holding "people's names, addresses and phone numbers". Anything that reaches
the VPC reads and writes it without credentials, in cleartext. `BASIC` also means no
replica and no persistence.

### Audit logging — both projects

```
auditConfigs: NONE
```

**Data Access audit logs are off in production.** No `google_project_iam_audit_config`
exists, so an `AccessSecretVersion` call against the vault's master key leaves no record.
This is the measured half of the 6.7.1 verdict, which until now rested on the *absence* of
a Terraform resource.

Log sinks: only `_Required` and `_Default` on both projects. No export to a tamper-evident
store.

| Bucket | Retention | Locked |
|---|---|---|
| `_Default` | 30 days | **no** |
| `_Required` | 400 days | yes |

`_Required` holds Admin Activity only. Application logs, Data Access and access patterns
all live in `_Default` — 30 days, unlocked, deletable by anyone with `roles/logging.admin`.

### IAM — production project bindings

| Binding | Note | CASA |
|---|---|---|
| `roles/editor` → default Compute SA **and** cloudservices agent | GCP defaults; the first is unused | **3.1.1** |
| `roles/secretmanager.secretAccessor` → `overslash-prod-run` | **Project-wide** — the API can read every secret in the project, not the 14 it is wired to | **6.7.1** |
| `roles/cloudsql.admin` → `overslash-prod-scheduler` | For a task that is one `settings.activationPolicy` PATCH, needing only `cloudsql.instances.update` | 3.1.1 |
| `roles/iam.serviceAccountUser` → `overslash-prod-build` | Project-wide — impersonation of any SA | 3.1.1 |
| `roles/owner` | **One human, no service accounts** — better than dev, which also has an automation SA at Owner | — |
| User-managed SA keys | **none**, on all three service accounts, in both projects | — |

The last row is a genuine positive and the answer to a question labs always ask.

### Cloud Run

| Service | Ingress |
|---|---|
| `overslash-prod-api` | **`all`** |
| `overslash-prod-overfwd` | **`all`** |
| `overslash-prod-shortener` | **`all`** |

`overslash-prod-api` sits behind the GCLB, so `all` means its raw `*.run.app` URL stays
directly reachable and bypasses the load balancer's host allowlist, its access logging, and
any Cloud Armor policy added later. The correct value for an LB-fronted service is
`INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`.

### Load balancer — production

| | |
|---|---|
| `gcloud compute ssl-policies list` | **empty** — the HTTPS proxy runs GCP's default profile |
| `gcloud compute security-policies list` | **empty** — no Cloud Armor |

No edge rate limiting, no OWASP managed ruleset, no adaptive protection, no geo/IP
blocking. And the TLS posture is unpinned: an external probe on 2026-09-22 showed
`api.overslash.com` negotiating TLS 1.2/1.3 and refusing 1.0/1.1, so the *effective* state
is fine — but nothing in the configuration says so, there is no declared policy to cite as
evidence, and a change to Google's default would move it silently.

### Secret Manager

16 secrets in each project. **None declares `rotation`, `nextRotationTime` or
`expireTime`.** Every consumer pins `version = "latest"`, so a rotation is a revision roll
rather than a config change — good — but nothing schedules, tracks or alerts on rotation
age, which is the shape of evidence 6.7.1 asks for.

### Monitoring — the count-gate, confirmed

| | |
|---|---|
| Alert policies deployed | **8**, all enabled |
| Uptime checks deployed | **0** |

The arithmetic matches `infra/` exactly: 12 policies declared, minus the 3 disabled at
`infra/env/prod.tfvars:113-119` (`api_latency`, `oauth_refresh`, `upstream_error`), minus
`[P0] API Down`, which is `count`-gated on `api_domain != ""` while prod sets
`domain = ""`. **So production has no GCM uptime check and no API-down page**; the only
deployed P0 is `API High 5xx Rate`, which cannot fire when the service is returning
nothing at all. Better Stack covers the detection out-of-band, but it is console-managed
and outside the reviewable configuration.

Deployed: `[P0] API High 5xx Rate`, `[P1]` API High CPU / API High Memory / Cloud SQL High
CPU / Cloud SQL High Disk / Background Task Stale / Webhook Delivery Failure Rate,
`[P2] API High 4xx Rate`. Every one is an availability or capacity signal — there is no
alert on any security event.

### Storage — production

| Bucket | UBLA | Public access prevention | Versioning | CMEK |
|---|---|---|---|---|
| `overslash-tfstate` | `true` | **enforced** | `true` | none |
| `overslash_cloudbuild` | **`false`** | **`inherited`** | none | none |

`overslash-tfstate` is configured correctly by `bin/bootstrap-tfstate.sh:32-62` — the only
gap is CMEK, which matters because versioning retains every historical value of the
generated `encryption-key` for 90 days.

`overslash_cloudbuild` is auto-created by Cloud Build, **not managed by Terraform**, and
holds source archives of the repository uploaded for each build — under legacy ACLs rather
than uniform bucket-level access, with public-access prevention merely inherited rather
than enforced. Same finding in dev.

### Supply chain and organization policy

Enabled on neither project: `containerscanning.googleapis.com`,
`containeranalysis`/`ondemandscanning`, `binaryauthorization.googleapis.com`,
`securitycenter.googleapis.com`. No image scanning, no deploy-time policy, no SCC. The
dependency tree is now scanned in CI (6.1.1, see
[dependency-vulnerability-policy.md](dependency-vulnerability-policy.md)), but the built
image — its base-layer OS packages in particular — is still scanned nowhere.

Organization policy constraints set on either project: **none**.
`sql.restrictPublicIp` · `iam.disableServiceAccountKeyCreation` · `run.allowedIngress` ·
`storage.publicAccessPrevention` · `iam.automaticIamGrantsForDefaultServiceAccounts` are
all unset. Every guardrail in this stack is convention expressed in HCL, so a `gcloud`
command or a console click moves the project outside it without failing anything.

---

## How this scan was run

`roles/viewer` on both projects is sufficient and is the right grant: it carries all 297
recommender permissions and `resourcemanager.projects.getIamPolicy` (the only way to read
`auditConfigs` — the console's IAM page does not show it), while **excluding**
`secretmanager.versions.access`, `storage.objects.get` and `cloudsql.instances.login`. A
Viewer cannot read secret payloads, Terraform state objects, or database contents.

Two gotchas worth recording for the next run:

- **Quota project.** `--project` selects the resource; the *quota* project comes from the
  active config. Set `CLOUDSDK_BILLING_QUOTA_PROJECT` to a project where the API is
  enabled and you hold `serviceusage.services.use` — `roles/viewer` does not include it,
  so production cannot bill itself. Unset it for `gcloud projects …` calls.
- **Cloud SQL recommenders are regional** (`--location=europe-west1`); IAM policy
  recommenders are `--location=global`. A sweep that only queries `global` silently
  returns nothing for Cloud SQL.
- `gcloud alpha` is not installed in this environment, so `gcloud alpha monitoring
  policies list` reports nothing and looks like a measurement. The Monitoring REST API
  (`monitoring.googleapis.com/v3/projects/<p>/alertPolicies`) is the reliable path.

---

## What this adds to the gap assessment

No verdict is overturned. It does three things:

1. **Converts inference into measurement on production** — 4.1.1 (`sslMode` permissive in
   prod, rated HIGH by Google), 6.7.1 (`auditConfigs: NONE`, project-wide `secretAccessor`,
   no rotation metadata), Cloud Run ingress, no SSL policy, no Cloud Armor, and the
   `deletion_protection = false` on the production database.
2. **Verifies one finding that had no evidence at all** — Memorystore has neither AUTH nor
   transit encryption. It has no dev counterpart, so until this scan it rested entirely on
   reading the module.
3. **Adds three findings the IaC could not show**: `roles/editor` on two GCP-default
   service accounts; the unmanaged `_cloudbuild` bucket holding repository source archives
   without uniform bucket-level access; and the confirmation that production runs 8 alert
   policies and **zero** uptime checks, so the `[P0] API Down` page does not exist.

And it supplies better evidence than prose: "Google's own Recommender rates this P2, with a
HIGH-severity insight behind it" is a stronger line in a submission than "we read our
Terraform and think it is unset" — and remediating a Recommender finding closes it in
Google's console, which is itself the artifact.
