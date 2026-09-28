# Server-side secrets access-control policy

Who can read Overslash's server-side secrets, through which path, and how every read is
logged and watched. This is the "documented access-control policy" CASA 6.7.1 asks for
("Securely store access tokens, API keys and server-side secrets"). The controls it
describes are Terraform in [`infra/modules/audit-logging/`](../../../infra/modules/audit-logging/),
not a paper process.

Adopted 2026-09-28. The retention, lock and alerting choices are recorded as D-NEXT in
[DECISIONS.md](../../../DECISIONS.md).

> **Status: written, not yet applied.** Infra is never auto-applied
> ([infra/README.md](../../../infra/README.md)). Until an operator runs the apply steps in
> [infra/README.md → Audit logging](../../../infra/README.md#audit-logging-casa-671), the
> logging and alerting sections describe the configuration in the repo, not the live
> projects. [gcp-posture.md](gcp-posture.md) records what was measured live.

---

## Scope

Two layers of secret exist. This policy covers the first and points at the second.

| Layer | What | Where it lives | Access control |
|-------|------|----------------|----------------|
| **Platform secrets** | The vault master key (`SECRETS_ENCRYPTION_KEY`), the JWT signing key, the database password, the system OAuth clients (login, GitHub, Google services), Stripe, the transactional-email key, the shortener and Mailbox Gateway keys, the trusted-proxy secret, the PagerDuty key, the BI role password, the OTel collector config | Google Secret Manager, one secret per value, `overslash-<env>-*`, in the `overslash` and `overslash-dev` projects | **This document** |
| **Tenant secrets** | Credentials an org or user stores in Overslash: API keys, OAuth access and refresh tokens | Postgres, AES-256-GCM under the master key (`overslash-core/src/crypto.rs`) | The product's permission chain (SPEC.md). Never returned by the API (Rule 3); injected at execution time only; every use written to the org audit log |

The master key is the hinge between the two: whoever reads `overslash-<env>-encryption-key`
can decrypt every tenant credential given a database dump. It gets no special IAM
treatment today (see [Known gaps](#known-gaps)), which is why the alert below matters.

---

## Who may read a secret payload

"Read" means `AccessSecretVersion` — fetching the payload. Listing secrets and reading their
metadata is not a payload read and is not restricted beyond project IAM.

| Principal | Access | Path | Why |
|-----------|--------|------|-----|
| `overslash-<env>-run@<project>.iam.gserviceaccount.com` | `roles/secretmanager.secretAccessor`, project-wide | Cloud Run resolves `secret_key_ref` env vars and secret volumes when an instance starts. No payload is ever placed in a plaintext env var or in the service spec | The only runtime identity. The API, the oversla.sh shortener, the overfwd Mailbox Gateway and the metrics-exporter job all run as it |
| Project Owners (humans) | Implicit via `roles/owner` | `tofu plan`/`apply` — the provider refreshes each `google_secret_manager_secret_version` by reading it, and reads the PagerDuty key as a data source. `bin/db-shell.sh` reads the database password. `gcloud secrets versions access` for break-glass | Operating the platform. **Every such read notifies** (below) |
| Everyone else | **None** | — | `roles/viewer` excludes `secretmanager.versions.access`. The Cloud Build and Scheduler service accounts hold no Secret Manager role. The BigQuery connection stores its own copy of the `bi` credential and never reads the secret |

**Writes.** A new version is added either by Terraform (generated values: DB password,
master key, signing key, BI password, OTel config) or by an Owner with
`gcloud secrets versions add` (externally issued values: OAuth clients, Stripe, email,
PagerDuty, gateway keys). `AddSecretVersion`, `DisableSecretVersion`, `DestroySecretVersion`
and every IAM change are Admin Activity audit logs, which GCP always writes.

**Adding a runtime reader.** A new service account that must read secrets at runtime is
added to `expected_secret_accessors` in [`infra/main.tf`](../../../infra/main.tf) in the
same PR that grants it. The module refuses a non-service-account entry, so a human can
never be exempted from the alert.

---

## How access is logged

| Control | Setting | Where |
|---------|---------|-------|
| Data Access audit logs | `ADMIN_READ`, `DATA_READ`, `DATA_WRITE` on `secretmanager.googleapis.com`, `cloudsql.googleapis.com`, `run.googleapis.com` (the Cloud SQL entry also makes pgAudit output visible) | `google_project_iam_audit_config.data_access` |
| Admin Activity audit logs | Always on (GCP default, cannot be disabled) | — |
| Retained copy | Sink `overslash-<env>-audit` routes **every** Cloud Audit Log in the project (`logName:"/logs/cloudaudit.googleapis.com%2F"`) to bucket `overslash-<env>-audit` in `europe-west1` | `google_logging_project_sink.audit` |
| Retention | **400 days** | `google_logging_project_bucket_config.audit` |
| Tamper evidence | Bucket retention **locked in production**, unlocked in dev | `audit_log_bucket_locked` in `infra/env/*.tfvars` |

Every `AccessSecretVersion` therefore produces an entry naming the caller
(`protoPayload.authenticationInfo.principalEmail`), the secret and version
(`protoPayload.resourceName`), the source IP and user agent, and whether it was allowed.
Denied attempts are logged too.

The `_Default` bucket keeps its own 30-day copy of the Data Access logs alongside
application logs; that bucket is unchanged. The retained, locked bucket is the evidence
store.

### Why 400 days

- CASA re-verification is every 12 months from the Letter of Assessment. A lab reviewing
  6.7.1 at revalidation should be able to see the whole prior cycle; 365 days leaves no
  slack for a late engagement, and 400 is 12 months plus five weeks.
- It matches GCP's own `_Required` bucket (400 days, locked), so Admin Activity and Data
  Access now age out together rather than one outliving the other.
- It is above the one-year floor common to the frameworks a customer will ask about next
  (PCI DSS 10.5.1 requires twelve months; SOC 2 reviewers commonly expect the same).
- It is cheap: see the cost estimate in [infra/README.md](../../../infra/README.md#audit-logging-casa-671).
  Longer is not much dearer, but a locked retention can never be changed, so the floor
  was chosen deliberately rather than generously.

### Why lock, and why only prod

A locked bucket cannot be deleted until its contents age out, its retention cannot be
changed, and the lock cannot be lifted by anyone — Owner, Terraform or Google support. That
is what makes the log tamper-evident: nobody who could read a secret can also erase the
record of having done so. Dev stays unlocked so the module can still be iterated on;
dev's audit trail is real but not evidence.

Deleting or editing the **sink** would stop *future* entries reaching the bucket. That
change is itself an Admin Activity log (`google.logging.v2.ConfigServiceV2.DeleteSink` /
`UpdateSink`), which GCP writes to `_Required` — 400 days, locked by Google — so it cannot
be done silently.

---

## How access is monitored

A log-based metric, `overslash-<env>-unexpected-secret-access`, counts every
`AccessSecretVersion` whose caller is **not** in `expected_secret_accessors` (today: the
run service account alone). It is labelled by principal and secret. A caller with no
principal email at all is counted.

The alert policy `[P1] overslash-<env> Unexpected Secret Access` fires on any non-zero
minute and emails the environment's alert address, naming the principal and the secret.
It is P1 (email), not P0 (page), because the common trigger is an operator's own
`tofu plan`.

**It fires on human reads by design.** A Terraform plan, a `db-shell.sh` session and a
break-glass `gcloud secrets versions access` all notify. The policy's position is that
every human read of a platform secret should be seen and attributable, and the cost is one
email per plan.

### Responding to an alert

1. **Recognise it.** Was it your own `tofu plan`/`apply`, `db-shell.sh` or a documented
   break-glass read, at the time shown? Note that on the incident and close it.
2. **If not**, treat the secret as exposed:
   1. Rotate it — add a new version, roll the consumers (a new Cloud Run revision picks
      up `latest`), then disable the old version. For the master key, follow the
      two-slot keyring rotation (`services/key_rotation.rs`).
   2. Find how the principal obtained access: `gcloud projects get-iam-policy` and the
      Admin Activity logs for `SetIamPolicy` in the audit bucket.
   3. Remove the grant, and record the incident.
3. If the principal is a new, legitimate runtime service account, the alert was right: it
   was granted without being declared. Add it to `expected_secret_accessors` in a PR.

---

## Review

- On every change to `expected_secret_accessors` or to any Secret Manager IAM grant — in
  the PR, by a reviewer.
- At least once per CASA cycle, before the evidence pack is assembled: re-run the
  verification below on both projects and re-read this document against it.

### Verifying the controls (evidence)

```bash
P=overslash   # or overslash-dev

# Data Access audit logging is on (was: auditConfigs NONE)
gcloud projects get-iam-policy $P --format=json | jq .auditConfigs

# Retained bucket: 400 days, locked (prod)
gcloud logging buckets describe overslash-prod-audit --location=europe-west1 --project=$P

# Sink routes audit logs there
gcloud logging sinks describe overslash-prod-audit --project=$P

# A secret read is recorded, with the caller
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Fdata_access" AND protoPayload.methodName:"AccessSecretVersion"' \
  --project=$P --bucket=overslash-prod-audit --location=europe-west1 --view=_AllLogs --limit=5 \
  --format='table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName)'
```

Reading Data Access entries needs `roles/logging.privateLogViewer`; `roles/viewer` sees
only Admin Activity.

---

## Known gaps

These are tracked in [TODO.md §1.6](../../../TODO.md) and are **not** closed by this policy.

- **The runtime grant is project-wide.** `overslash-<env>-run` can read every secret in the
  project, including the PagerDuty key it never uses. Per-secret
  `google_secret_manager_secret_iam_member` grants are the fix (the "least-privilege IAM"
  item). The alert does not cover this: a read by the run SA is by definition expected.
- **No rotation metadata.** No secret declares `rotation`, `next_rotation_time` or
  `expire_time`, and nothing alerts on rotation age.
- **Generated secrets live in Terraform state.** The DB password, the signing key and the
  master key are generated by `random_*` resources and so appear in plaintext in the
  `overslash-tfstate` bucket (versioned, 90-day history, no CMEK). Reading state is a path
  to those values that no Secret Manager audit log records; it is recorded only as a GCS
  object read, and only if GCS Data Access logs are on — they are not.
- **Memorystore** runs without AUTH or transit encryption (`overslash-prod-valkey`).
