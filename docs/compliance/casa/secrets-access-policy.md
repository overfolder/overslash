# Server-side secrets access-control policy

Who can read Overslash's server-side secrets, through which path, and how every read is
logged and watched. This is the "documented access-control policy" CASA 6.7.1 asks for
("Securely store access tokens, API keys and server-side secrets"). The controls it
describes are Terraform in [`infra/modules/audit-logging/`](../../../infra/modules/audit-logging/),
not a paper process.

Adopted 2026-09-28. The retention, lock and alerting choices are recorded as D112 in
[DECISIONS.md](../../../DECISIONS.md).

> **Status: written, not yet applied.** Infra is never auto-applied
> ([infra/README.md](../../../infra/README.md)). Until an operator runs the apply steps in
> [infra/README.md → Audit logging](../../../infra/README.md#audit-logging-casa-671), the
> logging and alerting sections describe the configuration in the repo, not the live
> projects. The per-workload grants below **are** applied (2026-10-23, both projects,
> verified per [least-privilege-iam.md](../../runbooks/least-privilege-iam.md)).
> [gcp-posture.md](gcp-posture.md) records what was measured live. The
> [Rotation](#rotation) section is also written and not yet applied: its apply and verify
> steps are in [secret-rotation.md](../../runbooks/secret-rotation.md).

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
| `overslash-<env>-run@` — **the API** | `roles/secretmanager.secretAccessor` on the project, under the IAM condition **every secret named `overslash-<env>-*` except the operator-only list** (today: `overslash-<env>-pagerduty-integration-key`) | Cloud Run resolves `secret_key_ref` env vars and secret volumes as the revision's identity when an instance starts. No payload is ever placed in a plaintext env var or in the service spec | The API reads nearly every platform secret, including ones other modules create (BI password, cache CA, OTel config), so its grant is a naming rule rather than a list. `infra/modules/secret-manager` (`api_secret_accessor`) |
| `overslash-<env>-shortener@` — oversla.sh | `secretAccessor` on `overslash-<env>-shortener-api-key` and `<cache instance>-server-ca`, nothing else | Same | `infra/modules/cloud-run-shortener` (one grant per `env_secrets` entry). Prod only |
| `overslash-<env>-overfwd@` — Mailbox Gateway | `secretAccessor` on `overslash-<env>-overfwd-gateway-key`, nothing else | Same | `infra/modules/cloud-run-overfwd` |
| `overslash-<env>-exporter@` — metrics-exporter job | `secretAccessor` on `overslash-<env>-db-password`, nothing else. Also `roles/secretmanager.viewer` on the project, which is metadata only and reads no payload | Same. The viewer role backs the hourly [rotation age sweep](#how-age-is-watched) | `infra/modules/metrics-exporter-job`, `infra/modules/iam` |
| Project Owners (humans) | Implicit via `roles/owner` | `tofu plan`/`apply` — the provider refreshes each `google_secret_manager_secret_version` by reading it, and reads the PagerDuty key as a data source. `bin/db-shell.sh` reads the database password. `gcloud secrets versions access` for break-glass | Operating the platform. **Every such read notifies** (below), except Terraform reads by a listed `terraform_operators` principal |
| Everyone else | **None** | — | `roles/viewer` excludes `secretmanager.versions.access`. No payload-reading role is project-wide without a condition. The Cloud Build and Scheduler service accounts hold no Secret Manager role. The BigQuery connection stores its own copy of the `bi` credential and never reads the secret |

**Writes.** A new version is added either by Terraform (generated values: DB password,
master key, signing key, BI password, OTel config) or by an Owner with
`gcloud secrets versions add` (externally issued values: OAuth clients, Stripe, email,
PagerDuty, gateway keys). `AddSecretVersion`, `DisableSecretVersion`, `DestroySecretVersion`
and every IAM change are Admin Activity audit logs, which GCP always writes.

**Adding a secret.** Give it a `rotation-class` label and the matching `rotation` block
([Rotation](#rotation)), or the age sweep reports it as unmeasured. A secret the API reads is named `overslash-<env>-<name>`: the name
alone grants it, and no IAM change is needed. A secret only Terraform or an operator reads
is also named `overslash-<env>-*`, so it must be added to `operator_only_secrets` in
[`infra/modules/secret-manager/main.tf`](../../../infra/modules/secret-manager/main.tf) in
the PR that creates it. Without that the API can read it. A secret one of the other
workloads reads is granted to that workload by name in its own module, next to the
`secret_key_ref` that consumes it. A secret outside the `overslash-<env>-` namespace is
readable by no workload until one is granted it explicitly.

**Adding a runtime reader.** A new workload gets its own service account in
[`infra/modules/iam`](../../../infra/modules/iam/main.tf). Do not reuse the API's: its
grant is the broad one. The new account is added to `expected_secret_accessors` in
[`infra/main.tf`](../../../infra/main.tf) in the same PR that grants it, and the module
refuses a non-service-account entry there.

**Terraform operators.** `terraform_operators` (per environment, in `infra/env/*.tfvars`)
lists the principals — humans or service accounts — whose `tofu plan`/`apply` reads do not
alert. Only reads whose user agent carries `terraform-provider-google/` are exempt; the same
principal reading through the Console, `gcloud` or `bin/db-shell.sh` still notifies. Adding
a principal is a reviewed PR.

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
four workload service accounts above, where they exist), leaving out Terraform-provider reads by a `terraform_operators`
principal. It is labelled by principal and secret. A caller with no principal email at all
is counted.

The alert policy `[P1] overslash-<env> Unexpected Secret Access` fires on any non-zero
minute and emails the environment's alert address, naming the principal. It opens one
incident per principal, so a session that reads every secret is one email, not one per
secret. It is P1 (email), not P0 (page), because the common trigger is an operator's own
read.

**It fires on interactive human reads by design.** A `db-shell.sh` session, a Console view
and a break-glass `gcloud secrets versions access` all notify, as does a Terraform run by
anyone not in `terraform_operators`. A listed operator's Terraform reads are routine — every
plan reads every secret — so they are not alerted on, but they remain in the retained audit
bucket, attributable to the principal. The exemption keys on a caller-supplied user agent,
so it trusts the operator's credential, not the header: a stolen operator credential could
read quietly by imitating the provider. That is the accepted cost of not training operators
to ignore the alert.

### Responding to an alert

1. **Recognise it.** Was it a `tofu plan`/`apply` by a non-operator, your own
   `db-shell.sh` or Console view, or a documented break-glass read, at the time shown? Note that on the incident and close it.
2. **If not**, treat the secret as exposed:
   1. Rotate it now, by its class in [Rotation procedures](#rotation-procedures). Do not
      wait for its period.
   2. Find how the principal obtained access: `gcloud projects get-iam-policy` and the
      Admin Activity logs for `SetIamPolicy` in the audit bucket.
   3. Remove the grant, and record the incident.
3. If the principal is a new, legitimate runtime service account, the alert was right: it
   was granted without being declared. Add it to `expected_secret_accessors` in a PR.

---

## Rotation

Secret Manager does not rotate anything. At a secret's `next_rotation_time` it publishes a
`SECRET_ROTATE` event and moves the time on by `rotation_period`, and that is all. So
rotation here has three parts: metadata that declares each secret's period, a reminder when
the calendar date arrives, and an age sweep that checks whether anyone actually rotated.
The settings are in [`infra/modules/secret-manager/rotation.tf`](../../../infra/modules/secret-manager/rotation.tf).
The reasoning is recorded as a decision in [DECISIONS.md](../../../DECISIONS.md).

**No platform secret rotates unattended.** Each stored credential has a consumer that must
change with it, and an unattended rotator would need write access to the vault master key,
the database and the Cloud Run services, in a repository where infrastructure is applied by
hand. What is automatic is the part that protects against forgetting: the reminder and the
alert. The only credentials that really rotate themselves are the ones no longer stored,
below.

### Classes and periods

| Class | Period | Who rotates it | Why this period |
|-------|--------|----------------|-----------------|
| `root-key` | 365 days | Operator. Value generated, never seen by anyone | A key's cryptoperiod, and each rotation is a planned operation: re-encrypting every tenant credential, or signing every user out |
| `database` | 180 days | Operator, with `tofu apply -replace`. Value generated by Terraform | One command, but a short window where new connections fail |
| `internal-key` | 180 days | Operator. Value generated, no third party | Shared by two of our own services, so it is cheap and only needs a back-to-back roll |
| `third-party` | 365 days | Operator, at the issuer's console | Needs a human at each issuer, and each issuer allows an overlap, so it is low risk and low frequency |
| `sa-key` | 90 days | Operator | A long-lived Google service-account private key, Google's recommended ceiling |
| `exempt` | None | Nobody | Not a credential, or nothing reads it. Labelled so the sweep skips it on purpose |

CASA 6.7.1 sets no period, so these are ours to set and defend.

### Every secret

`<env>` is `dev` or `prod`, in the `overslash-dev` and `overslash` projects.

| Secret (`overslash-<env>-…`) | Class | Procedure | Consumers |
|------------------------------|-------|-----------|-----------|
| `encryption-key` | `root-key` | [Master key](#master-key) | API |
| `signing-key` | `root-key` | [Signing key](#signing-key) | API |
| `db-password` | `database` | [Database passwords](#database-passwords) | API, metrics exporter, `bin/db-shell.sh` |
| `bi-db-password` (prod) | `database` | [Database passwords](#database-passwords) | API at boot, BigQuery connection |
| `overfwd-gateway-key` | `internal-key` | [Shared internal keys](#shared-internal-keys) | API, overfwd |
| `shortener-api-key` | `internal-key` | [Shared internal keys](#shared-internal-keys) | API, oversla.sh (prod only; dev's API uses a copy of prod's key) |
| `trusted-proxy-secret` | `internal-key` | [Trusted-proxy secret](#trusted-proxy-secret) | API, Vercel middleware |
| `oauth-client-secret`, `github-auth-client-secret` | `third-party` | [Issued keys](#issued-keys) | API (login) |
| `<provider>-services-client-secret` (google, github, notion, slack, hubspot) | `third-party` | [Issued keys](#issued-keys) | API (system OAuth clients) |
| `stripe-secret-key`, `stripe-webhook-secret` | `third-party` | [Issued keys](#issued-keys) | API |
| `email-api-key` | `third-party` | [Issued keys](#issued-keys) | API |
| `pagerduty-integration-key` (prod) | `third-party` | [PagerDuty key](#pagerduty-key) | Terraform only, into the notification channel |
| `google-directory-sa-key` | `sa-key` | [Directory key](#directory-key) | API |
| `oauth-client-id`, `github-auth-client-id`, `<provider>-services-client-id` | `exempt` | Public identifiers, sent in every authorize URL. They change only if the client is replaced | API |
| `otel-collector-config` | `exempt` | A rendered config file with no credential in it | OTel sidecar |
| `<cache instance>-server-ca` (prod) | `exempt` | Public CA material, issued and rotated by Memorystore. A re-apply picks up a new CA | API, oversla.sh |
| `pagerduty-integration-key` (dev) | `exempt` | Holds `REPLACE_ME`; `pagerduty_enabled` is off, so nothing reads it | None |

**Memorystore has no stored credential to rotate.** The cache moved to IAM auth
([memorystore-valkey.md](../../runbooks/memorystore-valkey.md)): each client presents a
one-hour access token for its service account, refreshed automatically. There is no
`valkey-auth` secret in Terraform. The `overslash-prod-valkey-auth` and
`-valkey-server-ca` secrets still in the prod project are leftovers of the deleted Redis
instance, with no owner in Terraform and no metadata. The sweep reports both as unmeasured
until step 8 of that runbook deletes them.

`expire_time` and `ttl` are not used on any secret. They delete the secret when they
elapse, which would take the API down instead of telling someone.

### How age is watched

Two signals, because they answer different questions.

| Signal | Asks | Mechanism |
|--------|------|-----------|
| `[P2] Secret Rotation Due` | Has the calendar date arrived? | `SECRET_ROTATE` lands on topic `overslash-<env>-secret-rotation` and waits on subscription `overslash-<env>-secret-rotation-due`, which keeps only those events, for 7 days. The alert fires while one waits |
| `[P2] Secret Rotation Overdue` | Is the secret really older than its period? | The metrics exporter ([`secret_rotation.rs`](../../../crates/overslash-metrics-exporter/src/secret_rotation.rs)) reads each secret's period and the create time of its newest enabled version, once an hour, and writes `secret_version_age_days{secret,rotation_class}` and `secret_rotation_overdue_days{secret,rotation_class}`. It fires, one incident per secret, on any non-zero value, and stays open until a new version exists |

The calendar and the age are independent. The reminder ignores real rotations: rotating
early does not move `next_rotation_time`, and the first reminder is counted from the apply,
not from the version's date. **The overdue alert is the control. The due alert is a nudge.**

The same policy fires on `secret_rotation_unmeasured` above zero: a secret with no class, no
period, or no enabled version, each named in the exporter's `secret cannot be measured`
WARN log. That catches a secret made by hand or added without a class. It also fires if the
sweep stops reporting for 3 hours. A failed sweep logs `Secret rotation sweep failed` and
leaves the other business metrics alone.

Both alerts are P2, email only. A secret past its period is a schedule slip, not an
exposure. An exposure is `[P1] Unexpected Secret Access`, which needs an immediate rotation
whatever the age.

**What age cannot see.** It reads the newest version's date, not its value, because the
sweep cannot read payloads. A version that was added with the same value looks fresh. A
placeholder looks like a credential: `REPLACE_ME` versions count from the day Terraform
wrote them.

### Rotation procedures

Dev first, every time. Set the variables once:

```bash
ENV=dev; P=overslash-dev   # or ENV=prod; P=overslash
R=europe-west1
# Force a fresh revision, so instances re-resolve `latest`. Removing the label afterwards
# keeps the next plan clean, at the cost of a second revision.
roll() {
  gcloud run services update "overslash-$ENV-$1" --project=$P --region=$R --update-labels=rotated-at=$(date +%s)
  gcloud run services update "overslash-$ENV-$1" --project=$P --region=$R --remove-labels=rotated-at
}
```

Every consumer except the master key mounts `latest`, and Cloud Run resolves it when an
instance starts. So a new version reaches a running service only after a roll, while any
instance that autoscales up in between already has it. Roll straight after adding a
version, off-peak.

**Finish every rotation** by disabling the old version:
`gcloud secrets versions disable <n> --secret=<id> --project=$P`. Until then the old value
stays readable. Terraform ignores `enabled` on the generated
versions it created, so it will not re-enable one.

#### Master key

`SECRETS_ENCRYPTION_KEY` is the only secret pinned to a version number. Under `latest`, a
new version would reach any instance that starts before the deploy, and that instance would
stamp the old key id on ciphertext written under the new key. The keyring has two slots: the
active key, and a decrypt-only previous key. Every ciphertext carries the id of the key that
wrote it. [`tests/key_rotation.rs`](../../../crates/overslash-api/tests/key_rotation.rs)
exercises this flow against Postgres, but **it has not been run on a deployed environment**:
drill it on dev before prod.

The three values below are in `infra/env/<env>.tfvars`. Assume today's are version `1`, id
`1`, and substitute the real ones.

1. Add the new key. Nothing reads it yet, because every revision is pinned:

   ```bash
   openssl rand -hex 32 | tr -d '\n' | \
     gcloud secrets versions add overslash-$ENV-encryption-key --project=$P --data-file=-
   ```

   It goes straight into Secret Manager, so unlike the first key it is not in Terraform
   state. The first rotation therefore also takes the live master key out of state.

2. Switch to the new key, keeping the old one for reads, and apply:

   ```hcl
   encryption_key_version          = "2"
   encryption_key_active_id        = 2
   encryption_key_previous_version = "1"
   ```

   Expect one revision. While traffic moves, an old-revision instance cannot read ciphertext
   the new revision has just written, so that request fails until the old instance drains.
   Reads of anything older keep working. Do this off-peak. Confirm `/health` is 200 and a
   stored secret still resolves.

3. Re-encrypt from a host with the Auth Proxy and the `overslash` CLI (the path
   `bin/db-shell.sh` uses). This reads both keys and the DB password, so it fires
   `[P1] Unexpected Secret Access` on purpose. Note it on the incident.

   ```bash
   cloud-sql-proxy --port=15432 $P:$R:overslash-$ENV-db &
   read_secret() { gcloud secrets versions access "$2" --secret="overslash-$ENV-$1" --project=$P; }
   export DATABASE_URL="postgres://overslash:$(read_secret db-password latest)@127.0.0.1:15432/overslash"
   export SECRETS_ENCRYPTION_KEY=$(read_secret encryption-key 2)
   export SECRETS_ENCRYPTION_KEY_PREVIOUS=$(read_secret encryption-key 1)
   export SECRETS_ENCRYPTION_KEY_ACTIVE_ID=2
   cargo build --release -p overslash-cli && PATH=target/release:$PATH
   overslash admin reencrypt --dry-run   # expect 0 errors
   overslash admin reencrypt
   overslash admin reencrypt --dry-run   # expect 0 re-encrypted, 0 errors
   ```

   The walker compare-and-swaps each row, so it is safe beside live traffic and safe to
   re-run. Any error means a row it cannot decrypt, perhaps tagged with a third key. Stop
   there and investigate: step 4 would strand that row.

4. Drop the old key from the keyring, and apply:

   ```hcl
   encryption_key_previous_version = ""
   ```

   `encryption_key_active_id` stays at `2` forever. It only ever goes up.

5. Disable version 1. **Do not destroy it** while any Cloud SQL backup from before step 3
   exists (7 are kept, plus 7 days of point-in-time recovery): those hold ciphertext only
   that key can read, so restoring one needs it. Add it back as the previous key to do so.

#### Signing key

`SIGNING_KEY` has one slot: no previous key is accepted. Every HS256 token dies with it. That
is dashboard sessions, MCP access tokens, secret-request links and in-flight MCP request
state. Users sign in again; MCP clients go through their refresh path. Stored data is not
affected, because nothing at rest is derived from this key. Announce it, and do it off-peak.

```bash
openssl rand -hex 32 | tr -d '\n' | \
  gcloud secrets versions add overslash-$ENV-signing-key --project=$P --data-file=-
roll api
gcloud secrets versions disable <old> --secret=overslash-$ENV-signing-key --project=$P
```

#### Database passwords

Terraform owns both, so the value is generated and applied in one step, with nobody seeing
it. Cloud SQL does not drop open connections when a password changes, but the API's pool
cannot open new ones until the roll, so roll immediately after the apply. Expect brief
errors if an instance needs a new connection in that window. The metrics exporter reads
`latest` on each run and needs nothing.

```bash
# db-password
cd infra && tofu workspace select $ENV
tofu apply -var-file=env/$ENV.tfvars -replace=module.secret_manager.random_password.db_password
cd .. && roll api

# bi-db-password (prod). The API sets the role's password at boot, and the BigQuery
# connection takes it from the same apply. Reports fail until the roll finishes.
cd infra && tofu apply -var-file=env/prod.tfvars -replace='module.bi[0].random_password.bi'
cd .. && roll api
```

Read the plan first. It must replace the password and its secret version, and update the
`google_sql_user` or BigQuery connection, and nothing else. The old version is disabled, not
destroyed (`deletion_policy = "DISABLE"`). These two values stay in Terraform state.

#### Shared internal keys

The two services hold one value, so roll them back to back. Calls between them fail with 401
until both are up. For `overfwd-gateway-key`, the steps are in
[mailbox-gateway.md](../../runbooks/mailbox-gateway.md#rotation).

`shortener-api-key` crosses projects: prod runs the only oversla.sh, and dev's API calls it
with a copy of prod's key. So there is one value, in two secrets. Rotate prod, then copy it.
The copy reads a payload, so it fires `[P1] Unexpected Secret Access`. Dev's short links fail
until its roll.

```bash
ENV=prod; P=overslash
openssl rand -base64 32 | tr -d '\n' | \
  gcloud secrets versions add overslash-prod-shortener-api-key --project=$P --data-file=-
roll shortener
roll api

gcloud secrets versions access latest --secret=overslash-prod-shortener-api-key --project=overslash | \
  gcloud secrets versions add overslash-dev-shortener-api-key --project=overslash-dev --data-file=-
ENV=dev; P=overslash-dev
roll api
```

#### Trusted-proxy secret

Shared with the dashboard's Vercel middleware. Until both sides match, the API does not trust
that hop, so audit rows and per-IP throttles see Vercel's address instead of the client's.
Nothing fails outright. It must be at least 32 bytes, or the API refuses to boot.

```bash
NEW=$(openssl rand -hex 32)
printf %s "$NEW" | gcloud secrets versions add overslash-$ENV-trusted-proxy-secret --project=$P --data-file=-
# Set the same value in the Vercel project's env for this environment, and redeploy it.
roll api
unset NEW
```

#### Issued keys

OAuth client secrets, Stripe and the email key are issued by someone else, and each issuer
can hold the old and new value at once. So nothing breaks if you go in this order: create
the new value, add the version, roll, then revoke the old value.

```bash
# Create the new value at the issuer, then, without it touching your shell history:
gcloud secrets versions add <secret> --project=$P --data-file=-   # paste, Enter, Ctrl-D
roll api
# Confirm a login, a connect, a charge or an email, per the secret. Then revoke the old value.
```

| Secret | Where to issue it | Overlap |
|--------|-------------------|---------|
| `oauth-client-secret`, `google-services-client-secret` | Google Cloud Console → Credentials → the client → Add secret | Two secrets at once |
| `github-auth-client-secret`, `github-services-client-secret` | GitHub → the OAuth App → Generate a new client secret | Two at once |
| `notion-`, `slack-`, `hubspot-services-client-secret` | The provider's app settings. Check first whether the provider allows an overlap; if not, expect failed token refreshes until the roll | Varies |
| `stripe-secret-key` | Stripe → Developers → API keys → Roll key, with an expiry | Set by you |
| `stripe-webhook-secret` | Stripe → the webhook endpoint → Roll secret | Up to 24 hours |
| `email-api-key` | Resend → API Keys. Create a new key, then delete the old | Until you delete it |

#### PagerDuty key

Nothing reads this at runtime: Terraform copies it into the notification channel, so a
rotation needs an apply, not a roll. Add a new integration key in PagerDuty, add the version,
then `make tofu-plan ENV=prod && make tofu-apply ENV=prod`. Prove it end to end by firing a
test alert before you delete the old integration key, because a broken key means P0s stop
paging, silently.

#### Directory key

The steps are in [google-directory.md](../../runbooks/google-directory.md#rotation). In prod,
key creation is **blocked** by the org's `iam.managed.disableServiceAccountKeyCreation`, and
prod has no opt-out. Setting one needs `orgpolicy.policy.set`, which a project Owner does not
have ([project-guardrails.md](../../runbooks/project-guardrails.md)). So each prod rotation
needs an org policy admin for the temporary opt-out, or the period will be missed.

### Evidence

A rotation is recorded without extra work: `AddSecretVersion` and `DisableSecretVersion` are
Admin Activity logs in the audit bucket, and the create times are in
`gcloud secrets versions list`. See
[secret-rotation.md](../../runbooks/secret-rotation.md#evidence).

---

## Review

- On every change to `expected_secret_accessors`, `terraform_operators` or to any Secret Manager IAM grant — in
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

- **The API's grant is wide by design.** `overslash-<env>-run` can read every
  `overslash-<env>-*` secret except the operator-only ones. That includes the shortener,
  overfwd and exporter credentials, which it legitimately shares, and it will include any
  future secret that is not added to `operator_only_secrets`. The alert does not cover this:
  any read by the API's account counts as expected. The narrower grants for the other three
  workloads are what keep a compromise of one of them from reaching the master key.
- **Rotation is operator-driven, and untested in production.** The metadata and alerts are
  written but not applied. Nothing rotates unattended, the master-key procedure has not been
  drilled on a deployed environment, and the signing key has one slot, so rotating it signs
  everyone out. See [Rotation](#rotation).
- **Generated secrets live in Terraform state.** The DB password, the signing key and the
  master key are generated by `random_*` resources and so appear in plaintext in the
  `overslash-tfstate` bucket (versioned, 90-day history, no CMEK). Reading state is a path
  to those values that no Secret Manager audit log records; it is recorded only as a GCS
  object read, and only if GCS Data Access logs are on — they are not. Rotating the master
  key and the signing key with `gcloud secrets versions add` takes the live values out of
  state. The two database passwords rotate through Terraform and stay in it.
- **Memorystore** ran without AUTH or transit encryption (`overslash-prod-valkey`). Fixed
  with AUTH + TLS ([memorystore-auth-tls.md](../../runbooks/memorystore-auth-tls.md)), and
  then moved to Memorystore for Valkey with **IAM auth**
  ([memorystore-valkey.md](../../runbooks/memorystore-valkey.md)): there is no stored
  password any more, in Secret Manager or in Terraform state. Clients present a
  one-hour access token for its own service account (the API's and the shortener's), each
  holding `memorystore.dbConnectionUser` on that instance only. Only the server CA
  (`<instance>-server-ca`, public material) is in Secret Manager.
