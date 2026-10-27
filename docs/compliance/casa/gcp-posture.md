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

**Remediation (2026-10-27).** Nothing depends on the default Compute SA: every Cloud Run
service and job, Cloud Build trigger and Scheduler job runs as its own account, there are no
instances, keys or `actAs` grants on it, and the one build ever run as it was the manual
submit of 2026-04-29. The cloudservices agent's 12 exercised permissions are all
`compute.instanceGroupManagers.*` / `instanceTemplates.*` / `instances.*` / `subnetworks.use`,
which is the prod VPC connector's managed instance group. Dev has no connector and its agent
holds no Editor.

- Dev's default-SA binding was **removed by hand on 2026-10-27**, and `overslash-dev-api`
  `/health` still returned 200.
- Prod was **applied on 2026-10-27**. `infra/modules/project-guardrails/` removes both
  bindings with `google_project_iam_member_remove` and grants the cloudservices agent
  `roles/compute.editor` first, but only where `use_private_vpc` (that is, where the
  connector exists). Re-measured the same day: prod's only Editor-class binding is
  `roles/compute.editor` on the cloudservices agent; dev has none. Prod `tofu plan` is clean.
- Both projects have since moved into the overspiral.com organization, which enforces
  `iam.automaticIamGrantsForDefaultServiceAccounts` and
  `iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` at org level. The
  module also pins both at project level, so the grants can come back neither by creation
  nor by a later grant, and a change of parent does not lift them.

Operator step: [project-guardrails.md](../../runbooks/project-guardrails.md).

---

## Measured configuration

### Cloud SQL

| Setting | **`overslash-prod-db`** | `overslash-dev-db` | Terraform | CASA |
|---|---|---|---|---|
| `sslMode` | **`ALLOW_UNENCRYPTED_AND_ENCRYPTED`** | same | `ENCRYPTED_ONLY` (`infra/modules/cloud-sql/main.tf:84`), not applied | **4.1.1** |
| `requireSsl` | `false` | `false` | unset — superseded by `sslMode` | **4.1.1** |
| `ipv4Enabled` | **`false`** — private IP on `overslash-prod-vpc` | `true`, public IP, **no authorized networks** | `!use_private_vpc` | 6.2.1 |
| `deletionProtectionEnabled` | **`false`** | `false` | `true`, both locks (`:54`, `:62`), not applied | — |
| `availabilityType` | `ZONAL` | `ZONAL` | `:60` | — |
| `tier` | `db-f1-micro` | `db-f1-micro` | tfvars | — |
| `databaseFlags` | `max_connections=100` only | same | `:97-140` adds connection logging + pgAudit, not applied | 6.7.1 |
| Backups / PITR | enabled, 7 retained, PITR on, 7-day transaction logs | same | `:87-96` | — |

Production is correctly private — that half of the dev/prod difference holds. What does
**not** hold is the SSL posture: `sslMode` was unset in the shared module, so production
accepts unencrypted connections too, and that is what Google rates **HIGH**.

`deletionProtectionEnabled: false` **on the production database** is confirmed live.

On the dev public IP, read it precisely: a public IP with *zero* authorized networks is not
an open database, because GCP denies direct connections when the allowlist is empty. The
finding is the permissive `sslMode` and the existence of the surface — one
`authorizedNetworks` entry away from reachable, with no `constraints/sql.restrictPublicIp`
to prevent that.

**Remediated in code, not yet applied** (`infra/modules/cloud-sql/main.tf`, both
environments): `ssl_mode = ENCRYPTED_ONLY`, `deletion_protection` in Terraform *and*
`deletion_protection_enabled` at the API, and the flags `log_connections`,
`log_disconnections`, `cloudsql.enable_pgaudit`, `pgaudit.log = ddl,role` and
`cloudsql.pgaudit_mask_literals`. A targeted plan against both live instances on
2026-09-28 showed exactly that: one in-place update each, nothing added or destroyed.
Every client was verified to arrive over the Auth Proxy before choosing
`ENCRYPTED_ONLY`. Apply steps and verification:
[cloud-sql-hardening.md](../../runbooks/cloud-sql-hardening.md). Re-measure this table
after the apply; until then the values above are still what is live.

#### Password-policy decision

The two P3 recommendations — `ENABLE_INSTANCE_PASSWORD_POLICY` and
`ENABLE_USER_PASSWORD_POLICY` — are **declined**, and will stay open in the console on
purpose. This is the written answer for 1.1.1.

- **No password prompt is reachable without IAM first.** Production has no public IP;
  dev's has zero authorized networks. The only way to a Postgres handshake is the Cloud
  SQL Auth Proxy (the Cloud Run volume, the BigQuery connection, `bin/db-shell.sh`), which
  requires `cloudsql.instances.connect` on the caller's Google identity before a byte of
  the Postgres protocol is exchanged. Online guessing by anyone without that grant is not
  possible, so the database password is a second factor behind IAM, not the perimeter.
- **No human chooses a database password.** The built-in users that log in are
  `overslash` (32 random alphanumerics, `random_password` in
  `infra/modules/secret-manager/main.tf`, read from Secret Manager) and `bi` (32 random
  alphanumerics from `infra/modules/bi`, created by the API). About 190 bits each.
  Minimum length and complexity rules add nothing to that — and Cloud SQL's default
  complexity demands a special character, which both generators leave out deliberately
  (`bi`'s is spliced into `ALTER ROLE` and is refused unless alphanumeric), so turning it
  on would reject our own credentials at the next rotation.
- **Lockout and expiry would be self-inflicted outages.** A failed-attempts lockout on
  `overslash` lets anything with `cloudsql.client` and a wrong password lock the
  production API out of its own database. Forced expiry without an automated rotation
  path (the password lives in Terraform state and Secret Manager and is read at boot)
  is a scheduled outage. Rotation belongs in a procedure, not a timer.
- **What we rely on instead:** IAM on the proxy, Secret Manager access control on the
  password, `log_connections` (every authentication attempt, success or failure, now
  lands in `cloudsql.googleapis.com/postgres.log`) and pgAudit's `role` class for
  password and privilege changes.

Two residuals, recorded rather than fixed here: humans still authenticate to Postgres
with the shared `overslash` password once through the proxy — **IAM database
authentication** for people would remove that shared credential and is the better next
step; and the default `postgres` built-in user exists on both instances (`gcloud sql users
list`) outside Terraform, with a password state this read-only scan cannot see. Confirm
it has none, or set a random one, as part of the 1.2.1 evidence.

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

*Remediation in code, pending apply (2026-10-13):* AUTH + `SERVER_AUTHENTICATION` in
`infra/modules/memorystore/main.tf`; see
[memorystore-auth-tls.md](../../runbooks/memorystore-auth-tls.md). The table above is
the live state until that runbook has been run.

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

**Remediation written, not applied (2026-09-28).** `infra/modules/audit-logging/` turns on
Data Access for Secret Manager, Cloud SQL (`cloudsql.googleapis.com`) and Cloud Run, sinks every Cloud Audit Log
to a 400-day `overslash-<env>-audit` bucket (locked in prod), and alerts on
`AccessSecretVersion` by anyone but the runtime SA. The measurements above stand until an
operator applies it; re-measure afterwards. Policy:
[secrets-access-policy.md](secrets-access-policy.md).

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

**The `secretAccessor` and `cloudsql.admin` rows: fixed and applied (2026-10-23), re-measured on both projects.**
`roles/secretmanager.secretAccessor` is no longer granted project-wide. Each workload has
its own service account (`-run` for the API, `-exporter`, `-shortener`, `-overfwd`). The
API's grant carries an IAM condition that admits only secrets named `overslash-<env>-*`
minus the operator-only PagerDuty key (`infra/modules/secret-manager`). The other three are
granted their secrets one by one: two for the shortener, one each for overfwd and the
exporter. The scheduler's `cloudsql.admin` becomes a two-permission custom role
(`cloudsql.instances.get` and `.update`), conditioned on the one instance and granted only
where night shutdown runs. Prod has none, so its scheduler holds no Cloud SQL role at all.
Re-measured 2026-10-23. `get-iam-policy` filtered on `secretAccessor` / `cloudsql.admin`
returns one row per project: `secretAccessor` → `overslash-<env>-run`, condition
"overslash-<env>-* secrets, minus operator-only". Dev's scheduler holds
`overslash_dev_sql_start_stop` conditioned on "overslash-dev-db only". Each Cloud Run service
and the exporter job run as their own account. `db-password` → `-exporter`,
`overfwd-gateway-key` → `-overfwd`, and in prod `shortener-api-key` and `cache-server-ca` →
`-shortener`. Apply and verify: [least-privilege-iam.md](../../runbooks/least-privilege-iam.md). Policy:
[secrets-access-policy.md](secrets-access-policy.md). The `serviceAccountUser` row is
unchanged.

### Cloud Run

| Service | Ingress, 2026-09-22 | Ingress, re-measured 2026-10-22 |
|---|---|---|
| `overslash-prod-api` | **`all`** | **`internal-and-cloud-load-balancing`** — `*.run.app/health` returns 404, `api.overslash.com/health` 200 |
| `overslash-prod-overfwd` | **`all`** | `all` |
| `overslash-prod-shortener` | **`all`** | `all` |
| `overslash-dev-api` | — | `all` |

**Production API: fixed and applied.** On 2026-09-22 `all` left the raw `*.run.app` URL
reachable, bypassing the load balancer's host allowlist, its access logging and Cloud
Armor. The service is now `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` (`infra/main.tf`, on
whenever `enable_api_lb` is), and a prod `tofu plan` is clean. Every caller was checked
first: none uses the `run.app` URL
([lb-hardening.md](../../runbooks/lb-hardening.md#what-changes-for-clients)).

**Accepted residuals.** `overslash-dev-api` has no LB. Its hosts are Cloud Run domain
mappings, which LB-only ingress would cut off. overfwd and the shortener have no LB in
either environment and authenticate their own callers (a bearer key, and a public redirect
service whose write path needs `API_KEY`). For all three, `all` is the only setting that
keeps them reachable.

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

Both are now declared in `infra/modules/api-lb/main.tf` — an SSL policy (TLS 1.2 minimum,
`RESTRICTED`) and a Cloud Armor policy (OWASP rules in preview). Apply steps and
verification: [lb-hardening.md](../../runbooks/lb-hardening.md).

**Re-measured 2026-10-22, applied:**

| | |
|---|---|
| `gcloud compute ssl-policies list` | `overslash-prod-api-ssl-policy`, `RESTRICTED`, `TLS_1_2`, on `overslash-prod-api-https-proxy` |
| `gcloud compute security-policies list` | `overslash-prod-api-armor`, on `overslash-prod-api-backend` (logging on) |

### Secret Manager

16 secrets in each project on 2026-09-22, and 30 in prod and 26 in dev on 2026-10-22.
Every one is named `overslash-<env>-*`, which is the namespace the API's
conditional grant matches. Two prod secrets, `overslash-prod-valkey-auth` and
`-valkey-server-ca`, belong to the deleted Memorystore for Redis instance. Their cleanup is
step 8 of [memorystore-valkey.md](../../runbooks/memorystore-valkey.md), and it is a
pre-flight of [least-privilege-iam.md](../../runbooks/least-privilege-iam.md).
**None declares `rotation`, `nextRotationTime` or `expireTime`.** Every consumer pins `version = "latest"`, so a rotation is a revision roll
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
holds a source archive of the repository — under legacy ACLs rather than uniform
bucket-level access, with public-access prevention merely inherited rather than enforced.
Same finding in dev.

Followed up 2026-10-21. Both buckets are in the `US` multi-region and each holds exactly one
archive, from a manual `gcloud builds submit` on 2026-04-29. No trigger writes there: all
three are GitHub-connected and clone from GitHub. The archive is a working-directory dump.
With no `.gcloudignore`, gcloud honoured `.gitignore` but not `.git/info/exclude`, so it
uploaded a local-only `.claude/settings.local.json`. Project viewers could read it through
the legacy `READER` ACL. **Fixed and applied 2026-10-23:** `infra/modules/cloud-build-source/`
imports both buckets with UBLA on, public-access prevention `enforced` and a 30-day delete
rule, and a root `.gcloudignore` closes the upload path. Re-measured on both projects:
UBLA `true`, prevention `enforced`, the lifecycle rule present, an empty `acl`, and no live
objects. Apply, archive deletion and evidence commands: [cloud-build-bucket.md](../../runbooks/cloud-build-bucket.md).

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

**Update 2026-10-27: both projects now sit in the overspiral.com organization, and the
baseline is applied.** The organization enforces a policy set at org level, and
`infra/modules/project-guardrails/` ([project-guardrails.md](../../runbooks/project-guardrails.md))
pins the Overslash-specific ones per project. Both applied on 2026-10-27; `tofu plan` is
clean in both environments. Effective policy, measured the same day with
`gcloud org-policies describe <constraint> --project=<p> --effective`:

| Constraint | `overslash` | `overslash-dev` | Set at | CASA |
|---|---|---|---|---|
| `iam.allowedPolicyMemberDomains` | org customer only | same | org | 3.1.1 |
| `iam.automaticIamGrantsForDefaultServiceAccounts` | enforced | enforced | org + project | 3.1.1 |
| `iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` | enforced | enforced | org + project | 3.1.1 |
| `iam.managed.disableServiceAccountKeyCreation` | enforced | **off** (Directory-sync key) | org; dev project opt-out | 6.7.1 |
| `iam.disableServiceAccountKeyUpload` | enforced | enforced | org | 6.7.1 |
| `iam.disableAuditLoggingExemption` | enforced | enforced | org + project | 6.7.1 |
| `sql.managed.restrictPublicIp` | enforced | **off** (public IP, no authorized networks) | org; dev project opt-out | 6.2.1 |
| `sql.managed.restrictAuthorizedNetworks` | enforced | **off** | org; dev project opt-out | 6.2.1 |
| `storage.publicAccessPrevention` | enforced | enforced | org + project | 6.2.1 |
| `storage.uniformBucketLevelAccess` | enforced | enforced | org | 6.2.1 |
| `storage.secureHttpTransport` | enforced | enforced | org | 4.1.1 |
| `compute.managed.requireOsLogin` | enforced | enforced | org | 3.1.1 |
| `compute.managed.disableSerialPortAccess` | enforced | enforced | org | 3.1.1 |
| `compute.skipDefaultNetworkCreation` | enforced | enforced | org | — |
| `compute.managed.restrictProtocolForwardingCreationForTypes` | `INTERNAL` only | same | org | — |
| `essentialcontacts.managed.allowedContactDomains` | `@overspiral.com` | same | org | — |
| `run.allowedIngress` | **unset** (allow all) | **unset** | — | 6.2.1 |

So the closing sentence above no longer holds: a `gcloud` command or console click that
would make a bucket public, add a public IP or an authorized network to the prod database,
mint or upload a service-account key, grant a default SA a basic role, or add an IAM member
from outside the organization now **fails** instead of drifting silently.

`iam.allowedPolicyMemberDomains` is why the public Cloud Run services moved to
`invoker_iam_disabled` instead of an `allUsers` binding. The old `allUsers` invoker
bindings were removed by hand on 2026-10-27; no Cloud Run service in either project has an
`allUsers` or `allAuthenticatedUsers` member, and `api.overslash.com/health`, the
shortener and `overslash-dev-api` still answer 200.

**Still open:** `run.allowedIngress` — it applies project-wide, so it can only be tightened
once overfwd and the shortener stop running with `INGRESS_TRAFFIC_ALL`.

---

### DNS — not in either project

Neither project has a Cloud DNS zone: `enable_dns = false` in both tfvars, and both zones are
on Namecheap BasicDNS, unsigned. The records GCP depends on — the Certificate Manager ACME
CNAME for the prod wildcard cert (`_acme-challenge.api`), the `ghs.googlehosted.com` CNAMEs
for every Cloud Run domain mapping, the GCLB A/AAAA — are therefore created by hand from
Terraform outputs. They are listed with their owning project in
[subdomain-inventory.md](subdomain-inventory.md) and checked daily against live DNS
(CASA 6.4.1). One finding: a `*.api.dev` wildcard CNAME to `ghs.googlehosted.com` with
only four names mapped in `overslash-dev`, accepted as a dev-only risk (only a Search Console
owner of the domain can create a mapping under it).

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
   without uniform bucket-level access (fixed and applied 2026-10-23 —
   [cloud-build-bucket.md](../../runbooks/cloud-build-bucket.md)); and the confirmation that production runs 8 alert
   policies and **zero** uptime checks, so the `[P0] API Down` page does not exist.

And it supplies better evidence than prose: "Google's own Recommender rates this P2, with a
HIGH-severity insight behind it" is a stronger line in a submission than "we read our
Terraform and think it is unset" — and remediating a Recommender finding closes it in
Google's console, which is itself the artifact.
