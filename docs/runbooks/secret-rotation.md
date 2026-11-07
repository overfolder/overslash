# Secret rotation metadata and alerts (CASA 6.7.1)

Infra is never auto-applied. This page is the human half of the change that gives every
platform secret a rotation class, and alerts when one is older than its period. The classes,
the periods and how to rotate each secret are in the policy:
[secrets-access-policy.md → Rotation](../compliance/casa/secrets-access-policy.md#rotation).
This page only applies and verifies the machinery.

## What changes

| | dev | prod |
|---|---|---|
| Topic `overslash-<env>-secret-rotation`, subscription `-secret-rotation-due`, Secret Manager service agent as publisher | created | created |
| `rotation-class` label on every Terraform-managed secret; `rotation` and `topics` on every one that is not `exempt` | 26 secrets updated | 28 updated |
| `roles/secretmanager.viewer` for `overslash-<env>-exporter@` (metadata only) | created | created |
| `deletion_policy = "DISABLE"` on the generated secret versions | state only | state only |
| `SECRETS_ENCRYPTION_KEY` pinned to version `1`, `SECRETS_ENCRYPTION_KEY_ACTIVE_ID=1` | one new API revision | one new API revision |
| `[P2] Secret Rotation Overdue`, `[P2] Secret Rotation Due` | after step 4 | after step 4 |

The new exporter image ships through Cloud Build as usual. Until the viewer role is applied,
each hourly sweep logs `Secret rotation sweep failed` with a 403 and the other metrics carry
on, so the order of the image and the apply does not matter.

**Not live until someone applies it.** Targeted read-only plans on 2026-11-07, with
`-refresh=false`, showed `module.secret_manager` and the Pub/Sub API as 5 to add, 29 to change
and 0 to destroy on both projects, with nothing replaced. A full plan was not possible from the
agent environment.

## 1. Plan and apply, dev

```bash
make tofu-plan ENV=dev
```

Check the plan before applying:

- No `must be replaced` and no `destroy` on `api_secret_accessor`, the API's only secret grant.
  If either appears, stop: something has put a pending change in the module's `depends_on`.
- `next_rotation_time` is a date one period away. On later plans it must not show: Secret
  Manager moves it, and every secret ignores that change.
- `~ secret_data_wo = (write-only attribute)` on secret versions is noise.

```bash
make tofu-apply ENV=dev
```

If an update fails with a permission error on the topic, the service agent's grant has not
propagated. Apply again after a minute. If the grant itself is refused by
`iam.allowedPolicyMemberDomains`, stop: the org policy is blocking a Google service agent, and
that needs an org admin. This is the one step no read-only plan could check.

## 2. Verify, dev

```bash
E=dev; P=overslash-dev; R=europe-west1

# Every secret is classified, and the non-exempt ones have a period and a topic.
gcloud secrets list --project=$P \
  --format='table(name.basename(),labels."rotation-class",rotation.rotationPeriod,rotation.nextRotationTime,topics[0].name.basename())'

# The exporter can list metadata and cannot read a payload.
gcloud projects get-iam-policy $P --flatten=bindings --filter="bindings.members:overslash-$E-exporter@" \
  --format='value(bindings.role)'
# Expect secretmanager.viewer, cloudsql.client and monitoring.metricWriter at project level.
```

Then prove the reminder end to end. Moving a date needs no secret to change:

```bash
S=overslash-$E-stripe-webhook-secret
gcloud secrets update $S --project=$P --next-rotation-time=$(date -u -d '+6 minutes' +%FT%TZ)
# Wait ~7 minutes.
gcloud pubsub subscriptions pull overslash-$E-secret-rotation-due --project=$P --auto-ack --limit=5 \
  --format='value(message.attributes.eventType,message.attributes.secretId)'
# Expect SECRET_ROTATE and this secret's name.
```

The date advances by one period after it fires, so nothing needs restoring.

Now the sweep. It runs on the first tick of each hour. Wait for one, or run the job within the
first five minutes of an hour:

```bash
gcloud run jobs execute overslash-$E-metrics-exporter --project=$P --region=$R --wait
gcloud logging read "resource.type=cloud_run_job AND resource.labels.job_name=overslash-$E-metrics-exporter AND severity>=WARNING" \
  --project=$P --freshness=1h --format='value(timestamp,jsonPayload.fields)' --limit=40
```

Expect `secret rotation overdue` for `overslash-dev-db-password` (see below), no
`secret cannot be measured`, and no `Secret rotation sweep failed`.

Confirm the descriptors exist, which the next step depends on:

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "x-goog-user-project: $P" \
  "https://monitoring.googleapis.com/v3/projects/$P/metricDescriptors?filter=metric.type%3Dstarts_with(%22custom.googleapis.com%2Foverslash%2Fbusiness%2Fsecret_%22)" \
  | jq -r '.metricDescriptors[].type'
```

## 3. Prod

Repeat steps 1 and 2 with `prod` and `P=overslash`. Prod also reports two unmeasured secrets,
`overslash-prod-valkey-auth` and `overslash-prod-valkey-server-ca`. They are the leftovers of
the deleted Redis instance, which have no owner in Terraform. Delete them per step 8 of
[memorystore-valkey.md](memorystore-valkey.md), or the alert in step 4 fires for them.

## 4. Switch on the alerts

Cloud Monitoring refuses a policy on a metric with no descriptor, which is why this is a
second apply. Per environment, once step 2 shows the three descriptors, set in
`infra/env/<env>.tfvars`:

```hcl
secret_rotation_alert_enabled = true
```

Land that in a PR, then `make tofu-plan ENV=<env> && make tofu-apply ENV=<env>`. Expect two
new alert policies.

## What will fire on day one

Measured from version create times on 2026-11-06, against the periods in the policy.

| Secret | Age | Period | Result |
|---|---|---|---|
| `overslash-dev-db-password` | 222 days | 180 | **Overdue** as soon as the alert exists |
| `overslash-prod-db-password` | 222 days | 180 | **Overdue** as soon as the alert exists |

That is the control working, not a false alarm: neither password has ever been rotated. Rotate
them per [Database passwords](../compliance/casa/secrets-access-policy.md#database-passwords),
dev first.

Next to come due, if nothing is rotated: dev's Directory key on 2026-12-29, prod's on
2027-01-06, dev's overfwd key on 2027-01-16 and prod's on 2027-01-20, then the master keys on
2027-03-29. Prod's Directory rotation needs an org policy admin
([Directory key](../compliance/casa/secrets-access-policy.md#directory-key)), so book that early.

## Evidence

For the CASA pack, once applied:

```bash
# Declared metadata, on both projects.
gcloud secrets list --project=$P --format=json | jq '[.[] | {name, labels, rotation}]'

# The age of every secret, as the sweep sees it. Metrics Explorer, or:
# custom.googleapis.com/overslash/business/secret_version_age_days

# The policies.
gcloud monitoring policies list --project=$P --filter='displayName:"Secret Rotation"' \
  --format='table(displayName,enabled)'

# A rotation having happened: who added which version, when.
gcloud logging read 'protoPayload.methodName:"AddSecretVersion"' --project=$P \
  --bucket=overslash-$E-audit --location=$R --view=_AllLogs --limit=10 \
  --format='table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName)'
```

## Rolling back

Rotation metadata changes nothing about how a secret is read, so there is nothing urgent to
undo. To silence the alerts, set `secret_rotation_alert_enabled = false`. To unpin the master
key, set `encryption_key_version = "latest"`, but only when no rotation is under way.
