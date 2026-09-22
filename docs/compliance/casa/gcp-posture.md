# GCP posture — live scan

What Google's own Recommender and the live project configuration say, as opposed to what
the Terraform says. Complements [gap-assessment.md](gap-assessment.md), which was written
from the IaC.

**Scope of this scan.** Measured against **`overslash-dev` only**. The production project
`overslash` was not reachable from the scanning account — see [Production](#production).
Rows marked *inferred* apply to prod because both environments are rendered from the same
modules in `infra/`; they are stated as inference, not measurement, and need re-running
against prod before they go into an evidence pack.

Scanned 2026-09-22. Re-run before each revalidation — Recommender output is generated from
a rolling observation window, so an empty result on a quiet project is not the same as a
clean one.

---

## Google Recommender findings

`gcloud recommender recommendations list --recommender=google.cloudsql.instance.SecurityRecommender --location=europe-west1`

| Priority | Subtype | Finding | CASA |
|----------|---------|---------|------|
| **P2** | `REQUIRE_SSL` | "Configure the instance to mandate SSL encryption for direct connections." `overslash-dev-db` | **4.1.1** |
| **P3** | `ENABLE_INSTANCE_PASSWORD_POLICY` | Instance-level password policy not enabled for built-in authentication users | 1.1.1 |
| **P3** | `ENABLE_USER_PASSWORD_POLICY` | No password expiry policy and no account lockout on consecutive failures | 1.1.1 |
| **P4** | `ENABLE_DATABASE_AUDITING` | Database auditing not enabled — no record of which user ran what | **6.7.1** |

`--recommender=google.iam.policy.Recommender --location=global`

| Priority | Finding | CASA |
|----------|---------|------|
| **P2** | `roles/editor` on `13553719731-compute@developer.gserviceaccount.com` — **the default Compute Engine service account** — unused for the entire observation window. Recommender's suggested operation is to remove the binding | **3.1.1** |

This one is worth dwelling on. The IaC audit correctly reported "no `roles/editor` in code" —
and that is true, `infra/modules/iam/main.tf` grants nothing of the sort. The binding is a
**GCP default**, created with the project and invisible to Terraform. It is exactly the
class of finding that reading the repo cannot produce, which is why this scan exists.

---

## Live configuration, measured

### Cloud SQL — `overslash-dev-db`

| Setting | Live value | Terraform | CASA |
|---------|-----------|-----------|------|
| `sslMode` | **`ALLOW_UNENCRYPTED_AND_ENCRYPTED`** | unset (`infra/modules/cloud-sql/main.tf:61-67`) | **4.1.1** |
| `requireSsl` | `false` | unset | **4.1.1** |
| `ipv4Enabled` | **`true`** (public IP `34.14.123.133`) | `!use_private_vpc`, and `infra/env/dev.tfvars:70` sets `use_private_vpc=false` | 6.2.1 |
| `authorizedNetworks` | **none** | none declared | — |
| `deletionProtectionEnabled` | **`false`** | `infra/modules/cloud-sql/main.tf:49` | — |
| `availabilityType` | `ZONAL` | `:55` | — |
| `databaseFlags` | `max_connections=100` only — no `pgaudit`, no `log_connections`, no `log_disconnections` | `:80-83` | 6.7.1 |
| `tier` | `db-f1-micro` | `infra/env/dev.tfvars` | — |
| Backups / PITR | enabled, 7 retained, PITR on, 7-day transaction log retention, logs in Cloud Storage | `:69-78` | — |
| Built-in users | `overslash`, `postgres` | — | 1.2.1 |

**Read the public-IP row precisely.** A public IP with *zero* authorized networks is not an
open database — GCP denies direct connections when the allowlist is empty, so the live
reachable path is the Cloud SQL Auth Proxy and the language connectors, both of which
authenticate through IAM. The finding is not "the database is on the internet". It is that
(a) `sslMode` permits unencrypted connections, which is what Recommender's P2 flags and
what 4.1.1 asks about, and (b) the public surface exists at all, one `authorizedNetworks`
entry away from being reachable, with no `constraints/sql.restrictPublicIp` org policy to
stop that happening. Prod sets `use_private_vpc=true` and has no public IP, so (b) is
dev-only; (a) is *inferred* to apply to prod too, because `ssl_mode` is unset in the shared
module.

`postgres` is the Cloud SQL built-in superuser. Confirm its password was set and is
non-default before answering 1.2.1 — the Test Guide's own wording exempts "Admin with a
user-defined password", so this is a question to answer, not a finding.

### IAM — project bindings

Full policy read on `overslash-dev`. Beyond the Recommender finding above:

| Binding | Note | CASA |
|---------|------|------|
| `roles/editor` → default Compute SA | GCP default, unmanaged, unused | **3.1.1** |
| `roles/owner` → `factory@software-factory-491814.iam.gserviceaccount.com` | An automation service account **from a different project** holds Owner on this one. Intentional (it is how this scan ran) but it is a standing cross-project Owner grant that a lab will ask about, and it should be time-bound or scoped down | **3.1.1** |
| `roles/cloudsql.admin` → `overslash-dev-scheduler` | Confirms the IaC finding live. The task it performs is one `settings.activationPolicy` PATCH, which needs `cloudsql.instances.update` | 3.1.1 |
| `roles/secretmanager.secretAccessor` → `overslash-dev-run` | **Project-wide.** The API can read every secret in the project, not the 14 it is wired to | **6.7.1** |
| `roles/iam.serviceAccountUser` → `overslash-dev-build` | Project-wide — impersonation of any SA in the project | 3.1.1 |
| User-managed service account keys | **none** on any of the three service accounts — a genuine positive, and the answer to a question labs always ask | — |

### Audit logging

```
auditConfigs: NONE
```

No `google_project_iam_audit_config` exists, so **Data Access audit logs are off** for
Secret Manager, Cloud SQL and Cloud Run. This is the measured confirmation of the
`gap-assessment.md` 6.7.1 verdict: the requirement's third clause is "access to secrets
shall be logged or monitored", and today an `AccessSecretVersion` call leaves no record.

Log sinks: only `_Required` and `_Default`. No export to a tamper-evident store.

| Bucket | Retention | Locked |
|--------|-----------|--------|
| `_Default` | 30 days | **no** |
| `_Required` | 400 days | yes |

`_Required` holds Admin Activity only. Everything an assessor would want to see —
application logs, Data Access, access patterns — is in `_Default`, at 30 days, unlocked,
and deletable by anyone with `roles/logging.admin`.

### Cloud Run

| Service | `run.googleapis.com/ingress` |
|---------|------------------------------|
| `overslash-dev-api` | **`all`** |
| `overslash-dev-overfwd` | **`all`** |

Confirms the IaC reading. On prod, where the API sits behind a GCLB, `all` means the raw
`*.run.app` URL stays directly reachable and bypasses the load balancer's host allowlist,
its access logging and any future Cloud Armor policy. *Inferred for prod* — re-measure.

### Secret Manager

16 secrets. **None declares `rotation`, `nextRotationTime` or `expireTime`.** Combined with
every consumer pinning `version = "latest"`, a rotation is a revision roll rather than a
config change — which is good — but nothing schedules, tracks or alerts on rotation age,
and that is the shape of evidence 6.7.1 asks for.

### Artifact Registry and build supply chain

| | |
|---|---|
| Repositories | `overslash-dev-registry` (standard), `overslash-dev-dockerhub` (remote/pull-through) |
| Encryption | Google-managed keys (no CMEK) |
| `containerscanning.googleapis.com` | **not enabled** |
| `containeranalysis` / `ondemandscanning` | **not enabled** |
| `binaryauthorization.googleapis.com` | **not enabled** |
| `securitycenter.googleapis.com` | **not enabled** |

No container image vulnerability scanning anywhere, which pairs with the CI-side finding
under 6.1.1 — neither the dependency tree nor the built image is scanned.

### Storage

| Bucket | UBLA | Public access prevention | CMEK | Versioning |
|--------|------|--------------------------|------|------------|
| `overslash-dev_cloudbuild` | **`false`** | `inherited` (not enforced) | none | none |

Auto-created by Cloud Build and not managed by Terraform. It holds **source archives of
the repository** uploaded for each build, under legacy ACLs rather than uniform
bucket-level access, with public-access prevention merely inherited rather than enforced.
The Terraform state bucket is configured correctly by `bin/bootstrap-tfstate.sh:32-62`
(UBLA, public-access-prevention, versioning) — this is a different bucket that nothing in
the repo created or governs.

### Organization policy

None of the constraints that would turn the above into guardrails are set:

`constraints/sql.restrictPublicIp` · `constraints/iam.disableServiceAccountKeyCreation` ·
`constraints/run.allowedIngress` · `constraints/compute.requireOsLogin` ·
`constraints/storage.publicAccessPrevention`

Every guardrail in this stack is convention expressed in HCL, so a `gcloud` command or a
console click can move the project outside it without failing anything.

---

## Production

**Not scanned.** The account this session authenticates as
(`factory@software-factory-491814.iam.gserviceaccount.com`) has no access to the
`overslash` project — `gcloud projects describe overslash` returns `PERMISSION_DENIED`, and
the project does not appear in `gcloud projects list`. It holds Owner on `overslash-dev`
and `overfolder-dev` only.

To complete the scan, either grant a read-only binding:

```
gcloud projects add-iam-policy-binding overslash \
  --member=serviceAccount:factory@software-factory-491814.iam.gserviceaccount.com \
  --role=roles/viewer
gcloud projects add-iam-policy-binding overslash \
  --member=serviceAccount:factory@software-factory-491814.iam.gserviceaccount.com \
  --role=roles/recommender.viewer
```

or run the scan directly and paste the output:

```
gcloud recommender recommendations list --project=overslash \
  --location=europe-west1 --recommender=google.cloudsql.instance.SecurityRecommender \
  --format="table(priority,recommenderSubtype,description)"
gcloud recommender recommendations list --project=overslash \
  --location=global --recommender=google.iam.policy.Recommender \
  --format="table(priority,description)"
gcloud projects get-iam-policy overslash --format=json     # bindings + auditConfigs
gcloud sql instances describe overslash-db \
  --format="json(settings.ipConfiguration,settings.databaseFlags,settings.deletionProtectionEnabled)"
gcloud logging sinks list --project=overslash
gcloud logging buckets list --project=overslash
gcloud run services list --project=overslash --region=europe-west1 \
  --format="value(metadata.name,metadata.annotations['run.googleapis.com/ingress'])"
gcloud redis instances list --project=overslash --region=europe-west1 \
  --format="value(name,authEnabled,transitEncryptionMode)"
```

The last one has no dev counterpart — Memorystore only exists where `use_private_vpc` is
true, so the `auth_enabled` / `transit_encryption_mode` finding in `gap-assessment.md`
6.7.1 is **unverified against a live instance** and rests on the module alone.

Two things to expect prod to differ on, both in prod's favour: no public Cloud SQL IP
(`use_private_vpc = true`), and `DEV_AUTH` unset. Everything else in this document is
rendered from the same modules and should be assumed present until measured.

---

## What this adds to the gap assessment

Nothing here overturns a verdict. It does three things:

1. **Confirms three `gap` rows by measurement rather than by reading HCL** — 4.1.1
   (Recommender's own P2 on `REQUIRE_SSL`), 6.7.1 (`auditConfigs: NONE`, project-wide
   `secretAccessor`, no secret rotation metadata), and the Cloud Run ingress reading.
2. **Adds two findings the IaC could not show**: `roles/editor` on the default Compute
   service account, and the unmanaged `_cloudbuild` bucket holding repository source
   archives without uniform bucket-level access.
3. **Supplies citable evidence.** "Google's own Recommender rates this P2" is a stronger
   line in a submission than "we read our Terraform and think it is unset" — and
   remediating a Recommender finding closes it in Google's console, which is itself the
   artifact.
