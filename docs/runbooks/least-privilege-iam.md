# Least-privilege IAM — applying it

Replaces the two project-wide grants Google's posture scan flagged
([gcp-posture.md](../compliance/casa/gcp-posture.md#iam--production-project-bindings)) with
grants scoped to what each identity actually does. The policy it implements is
[secrets-access-policy.md](../compliance/casa/secrets-access-policy.md).

| Before | After | Where | CASA |
|---|---|---|---|
| `roles/secretmanager.secretAccessor` → `overslash-<env>-run`, project-wide, and the API, shortener, overfwd and metrics exporter all run as `-run` | One service account per workload. Only the API keeps `-run`. Its `secretAccessor` carries a condition: secrets named `overslash-<env>-*`, minus `operator_only_secrets` (the PagerDuty key) | `infra/modules/iam`, `infra/modules/secret-manager` (`api_secret_accessor`) | 6.7.1 |
| (same grant) | `overslash-<env>-shortener` → `shortener-api-key` and the cache CA. `-overfwd` → `overfwd-gateway-key`. `-exporter` → `db-password`. Each is one `google_secret_manager_secret_iam_member` | `cloud-run-shortener`, `cloud-run-overfwd`, `metrics-exporter-job` | 6.7.1 |
| `roles/cloudsql.client`, `monitoring.metricWriter` → `-run` (shared with the exporter) | The exporter gets its own pair. The API keeps its own | `infra/modules/iam` | 3.1.1 |
| `roles/memorystore.dbConnectionUser` → `-run` (shared with the shortener) | A grant per client, keyed `api` / `shortener`, each still conditioned on the one instance. A `moved` block keeps the API's grant in place | `infra/modules/memorystore` | 3.1.1 |
| `roles/cloudsql.admin` → `overslash-<env>-scheduler`, in **every** environment | Custom role `overslash_<env>_sql_start_stop` (`cloudsql.instances.get`, `.update`), conditioned on the one instance, granted only where `enable_infra_scheduler` is on. Prod has it off, so the prod scheduler holds **no** Cloud SQL role | `infra/modules/infra-scheduler` | 3.1.1 |
| OTel config secret granted to `-run` on its own | Removed: the API's name rule covers it | `infra/modules/cloud-run` | — |

Infra is never auto-applied. This page is the human half.

## Why the API's grant is a name rule

The API reads nearly every platform secret, including secrets created by other modules (the
BI password, the cache CA, the OTel config). Listing them would mean a new
`*_iam_member` in each module that adds a secret. Forgetting one only shows up when a
revision fails to start. Instead, the condition admits everything in the environment's
namespace except an explicit exclusion list:

```
resource.name.startsWith("projects/<number>/secrets/overslash-<env>-")
  && resource.name != "projects/<number>/secrets/overslash-<env>-pagerduty-integration-key"
  && !resource.name.startsWith("projects/<number>/secrets/overslash-<env>-pagerduty-integration-key/")
```

The other workloads get explicit grants, because they read one or two secrets each.

Rules this creates, also written in the policy:

- **API secret:** name it `overslash-<env>-<name>`. No IAM change is needed.
- **Operator-only secret:** add it to `operator_only_secrets` in
  `infra/modules/secret-manager/main.tf` in the same PR.
- **Memorystore instance names keep the prefix** (`cache_instance_name`), because the
  API reads `<instance>-server-ca` under the rule.

## Apply — dev, then prod

Two applies. The first only **adds**: the new service accounts, every new grant except the exporter's, and the
widened alert allowlist. Nothing loses access yet. The second moves the workloads onto
their new accounts and **removes** the project-wide grants. Running it as one apply risks
a gap: Terraform may delete the unconditional `secretAccessor` before the conditional one
has propagated, and an API instance that starts in that window cannot resolve its secrets.

### Pre-flight (prod)

The two Memorystore for Redis secrets left over from
[memorystore-valkey.md](memorystore-valkey.md) step 8 are still in the project. The
name rule would let the API read the dead AUTH string, so delete them first:

```bash
P=overslash
gcloud secrets list --project=$P --format='value(name.basename())' | grep -v '^overslash-prod-'
# Expect: nothing. Every secret is in the namespace.
gcloud secrets delete overslash-prod-valkey-auth      --project=$P --quiet
gcloud secrets delete overslash-prod-valkey-server-ca --project=$P --quiet
```

### 1. Additive apply

`-target` cannot express this. The exporter module call has a whole-module
`depends_on = [module.iam]`, so targeting anything in it pulls in the deletions in
`module.iam` as well. Exclude the switch-and-remove resources instead. `-exclude`
cannot be combined with `-target`.

```bash
make tofu-init
cd infra && tofu workspace select dev   # then prod
tofu plan -var-file=env/dev.tfvars -out=dev-add.tfplan \
  -exclude=module.iam.google_project_iam_member.cloud_run_secret_accessor \
  -exclude=module.iam.google_project_iam_member.scheduler_sql_admin \
  -exclude=module.cloud_run.google_secret_manager_secret_iam_member.otel_config_accessor \
  -exclude=module.metrics_exporter_job.google_cloud_run_v2_job.exporter \
  -exclude='module.cloud_run_overfwd[0].google_cloud_run_v2_service.overfwd' \
  -exclude='module.cloud_run_shortener[0].google_cloud_run_v2_service.shortener'
# Expect 0 to destroy. Dev: 8 to add, 1 to change. Prod: 10 to add, 1 to change.
#   + module.iam.google_service_account.metrics_exporter, overfwd[0], shortener[0] (prod)
#   + module.iam metrics_exporter_sql_client, metrics_exporter_metric_writer
#   + module.secret_manager.google_project_iam_member.api_secret_accessor
#   + overfwd env_secrets["OVERFWD_API_KEY"]; shortener env_secrets["API_KEY"], ["VALKEY_CA_CERT"] (prod)
#   + memorystore client["shortener"] (prod); client shows "has moved to" client["api"]
#   + infra_scheduler custom role and its member (dev; prod has no scheduler)
#   ~ audit_logging unexpected_secret_access (its filter lists the new accounts)
# The exporter's own db_password grant is NOT here (same depends_on); it lands in step 2.
# Any other line is unrelated drift: stop and look at it before applying.
tofu apply dev-add.tfplan
```

Wait for propagation. Conditional bindings can take several minutes. Then confirm
that the API's conditional grant is live **before** going on:

```bash
P=overslash-dev; E=dev    # or overslash / prod
gcloud projects get-iam-policy $P --flatten=bindings \
  --filter="bindings.role=roles/secretmanager.secretAccessor" \
  --format='yaml(bindings.members,bindings.condition)'
# Expect two entries for overslash-$E-run: the old unconditional one and the new one with
# condition.title "overslash-$E-* secrets, minus operator-only".
```

### 2. Switch and remove

```bash
tofu plan -var-file=env/dev.tfvars -out=dev.tfplan
# Expect, and nothing else from this change:
#   - module.iam.google_project_iam_member.cloud_run_secret_accessor
#   - module.iam.google_project_iam_member.scheduler_sql_admin
#   - module.cloud_run.google_secret_manager_secret_iam_member.otel_config_accessor[0]
#   ~ module.metrics_exporter_job.google_cloud_run_v2_job.exporter     (service_account)
#   ~ module.cloud_run_overfwd[0].google_cloud_run_v2_service.overfwd  (service_account)
#   ~ module.cloud_run_shortener[0]...shortener                        (service_account, prod)
#   + module.metrics_exporter_job.google_secret_manager_secret_iam_member.db_password
#   ~ module.monitoring...pagerduty[0] (prod) and data sources "read during apply": cosmetic.
#     module.monitoring depends_on module.cloud_run, which has a change, so its reads are
#     deferred. The values are unchanged.
# The API service itself shows no change.
tofu apply dev.tfplan
```

The overfwd and shortener updates roll a new revision on their new account. A revision
that cannot read a secret never becomes Ready, and traffic stays on the old one, so a
mistake fails closed. If an update errors with "Permission denied on secret", it is IAM
propagation: wait a minute and re-run the plan/apply. The exporter's grant is created
in the same apply as its switch, so the first 5-minute tick afterwards can fail on
propagation. The next tick recovers, and step 5 below runs it explicitly.

## Verify — evidence for the CASA pack

Save the output of each block with the date.

```bash
P=overslash; E=prod; R=europe-west1     # or overslash-dev / dev
N=$(gcloud projects describe $P --format='value(projectNumber)')

# 1. No unconditional project-wide secretAccessor, and no cloudsql.admin, for anyone.
gcloud projects get-iam-policy $P --flatten=bindings \
  --filter="bindings.role:(roles/secretmanager.secretAccessor OR roles/cloudsql.admin)" \
  --format='table(bindings.role,bindings.members.flatten(),bindings.condition.title)'
# Expect exactly one row: secretAccessor, overslash-$E-run, "overslash-$E-* secrets, minus operator-only".

# 2. Each workload runs as its own account.
gcloud run services list --project=$P --region=$R \
  --format='table(metadata.name,spec.template.spec.serviceAccountName)'
gcloud run jobs list --project=$P --region=$R \
  --format='table(metadata.name,spec.template.spec.template.spec.serviceAccountName)'
# Expect: api → -run, overfwd → -overfwd, shortener → -shortener, metrics-exporter → -exporter.

# 3. Per-secret grants, and nothing else, on the secrets the other workloads read.
for s in db-password overfwd-gateway-key shortener-api-key cache-server-ca; do
  echo "== $s"; gcloud secrets get-iam-policy overslash-$E-$s --project=$P --format='value(bindings.members)' 2>&1
done
# Expect: db-password → -exporter; overfwd-gateway-key → -overfwd; shortener-api-key and
# cache-server-ca → -shortener (prod; the last two don't exist in dev).

# 4. Each grant admits what it should and refuses the rest. Policy Troubleshooter
#    evaluates the condition against the version name given.
check() {  # check <principal> <secret>
  gcloud policy-intelligence troubleshoot-policy iam \
    "//secretmanager.googleapis.com/projects/$P/secrets/$2" \
    --principal-email="$1@$P.iam.gserviceaccount.com" \
    --permission=secretmanager.versions.access \
    --resource-name="projects/$N/secrets/$2/versions/1" \
    --resource-type=secretmanager.googleapis.com/SecretVersion \
    --resource-service=secretmanager.googleapis.com \
    --format='value(overallAccessState)'
}
check overslash-$E-run      overslash-$E-encryption-key            # CAN_ACCESS
check overslash-$E-run      overslash-$E-pagerduty-integration-key # CANNOT_ACCESS
check overslash-$E-exporter overslash-$E-db-password               # CAN_ACCESS
check overslash-$E-exporter overslash-$E-encryption-key            # CANNOT_ACCESS
check overslash-$E-overfwd  overslash-$E-encryption-key            # CANNOT_ACCESS
check overslash-prod-shortener overslash-prod-signing-key          # CANNOT_ACCESS (prod)

# 5. Every workload still resolves its secrets: force a fresh API revision (the API's
#    spec did not change, so nothing has re-resolved its secrets under the new rule yet),
#    and run the exporter once.
gcloud run services update overslash-$E-api --project=$P --region=$R \
  --update-labels=iam-verified=$(date +%Y%m%d)
# Expect: the new revision goes Ready, and https://api.<env domain>/health is 200.
gcloud run services update overslash-$E-api --project=$P --region=$R --remove-labels=iam-verified
# (a second fresh revision, and Terraform sees no label drift on the next plan)
gcloud run jobs execute overslash-$E-metrics-exporter --project=$P --region=$R --wait
# Expect: the execution succeeds.

# 6. Scheduler (dev): start is a no-op on a running instance, so it is safe to fire.
gcloud scheduler jobs run overslash-dev-db-start --project=overslash-dev --location=$R
gcloud logging read --project=overslash-dev --freshness=10m --limit=5 \
  'resource.type="cloud_scheduler_job" resource.labels.job_id="overslash-dev-db-start"' \
  --format='table(timestamp,httpRequest.status,jsonPayload.status)'
# Expect: 200, not 403.
```

Afterwards, re-run the IAM block of [gcp-posture.md](../compliance/casa/gcp-posture.md)
and record the new bindings. Move the 6.7.1 and 3.1.1 notes in
[gap-assessment.md](../compliance/casa/gap-assessment.md) and the evidence-index row from
"pending apply" to applied.

## Rollback

Each change is an ordinary in-place revert. Revert the PR and apply. The project-wide
`secretAccessor` comes back on `-run`, and the workloads move back to it in the same apply.
If one workload is stuck now, without a revert, give its new account the missing secret
by hand:

```bash
gcloud secrets add-iam-policy-binding <secret> --project=$P \
  --member=serviceAccount:<sa>@$P.iam.gserviceaccount.com --role=roles/secretmanager.secretAccessor
```

Then fix the grant in the module so the next apply does not remove it.

Deleting the custom role on rollback leaves it soft-deleted for 7 days. If it is
re-created within 37 days, the google provider undeletes it rather than failing.

## Not covered here

- **Cloud Build's project-wide `roles/iam.serviceAccountUser`.** It lets the build account
  act as any service account. That includes the new ones, which is what keeps
  `gcloud run deploy` working for them. Narrowing it to `actAs` on the four workload
  accounts is a separate change ([TODO.md §1.6](../../TODO.md)).
- **The scheduler's project-wide `roles/run.invoker`.** It is used only for the exporter
  tick, and could be a grant on that one job.
- **Dev API ingress** stays `all`. See [lb-hardening.md](lb-hardening.md#what-changes-for-clients).
