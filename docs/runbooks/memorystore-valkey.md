# Memorystore for Valkey — cutover from Memorystore for Redis

`infra/modules/memorystore` used to create a Memorystore **for Redis 7.2** instance
(`google_redis_instance`, `overslash-<env>-valkey`) with a static AUTH string. It now
creates a Memorystore **for Valkey 9.1** instance (`google_memorystore_instance`,
`overslash-<env>-cache`). These are different products, so the cutover is a new
instance, not an upgrade:

| | Before | After |
|---|---|---|
| Resource | `google_redis_instance.valkey` | `google_memorystore_instance.cache` |
| Engine | Redis 7.2 | Valkey 9.1 (`valkey_engine_version`) |
| Name | `overslash-<env>-valkey` | `overslash-<env>-cache` (`cache_instance_name`) |
| Network | VPC peering (`authorized_network`) | Private Service Connect: a `gcp-memorystore` service connection policy on `overslash-<env>-subnet` |
| Auth | AUTH string in `overslash-<env>-valkey-auth` | **IAM auth**: each connection presents an access token for `overslash-<env>-run@`, which holds `roles/memorystore.dbConnectionUser` on this instance only |
| TLS | `SERVER_AUTHENTICATION`, CA in `overslash-<env>-valkey-server-ca` | Same mode, CA in `<instance>-server-ca` |
| Client env | `REDIS_PASSWORD` / `VALKEY_PASSWORD` | `REDIS_AUTH=gcp-iam` / `VALKEY_AUTH=gcp-iam` |

Memorystore for Valkey has no static AUTH string (its token auth is Preview and has no
Terraform surface), so IAM auth is how CASA 6.7.1 stays covered. The clients fetch tokens
from the metadata server and re-authenticate open connections every 30 minutes
(`crates/overslash-valkey/src/gcp_iam.rs`).

Only prod is affected: dev has `enable_valkey = false`.

## The plan: `state rm`, not destroy

Removing the old instance from Terraform state, rather than letting OpenTofu destroy it,
keeps it **running and unmanaged** through the cutover. Cloud Run keeps using it until
the apply moves both services over, and the previous revisions still point at it, so
rolling back is a traffic switch. You delete it by hand once you're satisfied.

## 1. Ship the code first

The API and oversla-sh images must contain this change before the apply. An old binary
does not understand `REDIS_AUTH` / `VALKEY_AUTH`: the API would connect without AUTH and
fall back to in-memory, and oversla-sh would crash-loop. The new binaries still accept
`REDIS_PASSWORD` / `VALKEY_PASSWORD`, so they are safe to deploy against the current
instance.

```bash
gcloud run services describe overslash-prod-api --region=europe-west1 --project=overslash \
  --format='value(spec.template.spec.containers[0].image)'
make shortener-deploy ENV=prod      # oversla-sh is deployed by hand
```

## 2. Take the old instance out of state

```bash
cd infra && tofu workspace select prod
tofu state rm \
  'module.memorystore[0].google_redis_instance.valkey' \
  'module.memorystore[0].google_secret_manager_secret.auth_string' \
  'module.memorystore[0].google_secret_manager_secret_version.auth_string' \
  'module.memorystore[0].google_secret_manager_secret.server_ca' \
  'module.memorystore[0].google_secret_manager_secret_version.server_ca'
```

All five keep existing in GCP. The state bucket is versioned, so this step can be undone
by restoring the previous state object.

Until this step is done, `make tofu-plan ENV=prod` fails with `Error: Cycle: …`. It would
otherwise plan to destroy the old instance alongside the `create_before_destroy` resources
that replace it. Treat the error as the reminder to run this step, never as something
to work around.

## 3. Create the new instance on its own

A targeted apply builds the instance, its PSC policy, the IAM binding and the CA secret,
but leaves Cloud Run on the old instance. Two reasons to split it out: IAM bindings take
minutes to propagate, and the TLS check in step 4 has to pass before any client moves.

```bash
tofu plan -var-file=env/prod.tfvars -target=module.memorystore -target=google_project_service.apis -out=valkey.tfplan
tofu apply valkey.tfplan
```

The plan may also print `Error decoding "module.cloud_sql.google_sql_database_instance.db"
from prior state: unsupported attribute "require_ssl"`. It is harmless and the plan still
succeeds: prod state was last written by the 5.x Google provider, and a targeted plan
leaves resources outside its targets un-upgraded. The full apply in step 5 rewrites them.

Expect: `+` the two APIs (`memorystore`, `networkconnectivity`), `+` the service
connection policy, instance, IAM member, secret and secret version. Expect `-` for
`google_project_service.apis["redis.googleapis.com"]` too; `disable_on_destroy = false`,
so this only forgets the API and doesn't disable it. Creating the instance takes several
minutes.

## 4. Pre-flight: TLS verifies by IP, and IAM auth works

The clients connect by IP, and rustls requires the server certificate to name that IP.
Google does not document the certificate's SANs for PSC endpoints, so prove it before
moving traffic. This job runs as the Cloud Run service account, so it also proves the
IAM binding has propagated:

```bash
P=overslash R=europe-west1
EP=$(gcloud memorystore instances describe overslash-prod-cache --location=$R --project=$P --format=json \
  | jq -c '.endpoints[].connections[].pscAutoConnection | select(.connectionType=="CONNECTION_TYPE_PRIMARY")')
IP=$(jq -r .ipAddress <<<"$EP"); PORT=$(jq -r .port <<<"$EP"); echo "$IP:$PORT"
gcloud run jobs create valkey-preflight --project=$P --region=$R \
  --image=alpine:3.21 --vpc-connector=overslash-prod-vpc-conn \
  --service-account=overslash-prod-run@overslash.iam.gserviceaccount.com \
  --set-secrets=/ca/ca.pem=overslash-prod-cache-server-ca:latest \
  --command=sh --args=-c,"apk add -q openssl curl valkey-cli jq && \
    openssl s_client -connect $IP:$PORT -CAfile /ca/ca.pem -verify_ip $IP -verify_return_error </dev/null 2>&1 | grep -E 'Verify return code|verify error'; \
    T=\$(curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token); \
    valkey-cli -h $IP -p $PORT --tls --cacert /ca/ca.pem --user default --pass \$T --no-auth-warning PING"
gcloud run jobs execute valkey-preflight --project=$P --region=$R --wait
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="valkey-preflight"' \
  --project=$P --limit=20 --format='value(textPayload)'
gcloud run jobs delete valkey-preflight --project=$P --region=$R --quiet
```

**Expect `Verify return code: 0 (ok)` and `PONG`.**

- `IP address mismatch`: **stop.** The clients would refuse the server. The fix is a
  client-side verifier that checks the chain against the pinned per-instance CA without
  matching the IP, which needs a code change. Nothing has moved yet, so prod is unaffected.
- `WRONGPASS` / `NOPERM`: the IAM binding has not propagated, or its condition does not
  match the instance. Wait a few minutes and re-run. If it persists, check the binding:
  `gcloud projects get-iam-policy overslash --flatten=bindings --filter='bindings.role:memorystore.dbConnectionUser'`.

## 5. Move Cloud Run over

```bash
make tofu-plan ENV=prod
```

Expect only `~` on `module.cloud_run.google_cloud_run_v2_service.api` (`REDIS_URL` now
the PSC IP, `REDIS_AUTH = "gcp-iam"`, `REDIS_CA_CERT` from `overslash-prod-cache-server-ca`,
`REDIS_PASSWORD` gone) and on `module.cloud_run_shortener[0]…shortener` (the same with
`VALKEY_*`). The PagerDuty notification channel always shows an update when the API list
changed; that's expected. Anything else is unrelated drift, so stop and look.

```bash
make tofu-apply ENV=prod
```

## 6. Optional: carry oversla.sh links over

The new keyspace starts empty. Rate-limit counters, the resolver cache and the session
cache rebuild on their own. Short links (`sh:*`, TTL at most 7 days) do not. To keep them,
copy them while both instances are up. Use `SET … NX` so links created on the new
instance since step 5 win:

```bash
OLD_IP=10.70.245.67   # the old instance's host; `gcloud redis instances describe overslash-prod-valkey`
gcloud run jobs create valkey-copy-links --project=$P --region=$R \
  --image=alpine:3.21 --vpc-connector=overslash-prod-vpc-conn \
  --service-account=overslash-prod-run@overslash.iam.gserviceaccount.com \
  --set-secrets=/old/ca.pem=overslash-prod-valkey-server-ca:latest,/old/pass=overslash-prod-valkey-auth:latest,/new/ca.pem=overslash-prod-cache-server-ca:latest \
  --command=sh --args=-c,"apk add -q curl valkey-cli jq && \
    T=\$(curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token); \
    old() { valkey-cli -h $OLD_IP -p 6378 --tls --cacert /old/ca.pem -a \$(cat /old/pass) --no-auth-warning \"\$@\"; }; \
    new() { valkey-cli -h $IP -p $PORT --tls --cacert /new/ca.pem --user default --pass \$T --no-auth-warning \"\$@\"; }; \
    n=0; for k in \$(old --scan --pattern 'sh:*'); do v=\$(old GET \$k); t=\$(old PTTL \$k); \
      [ \"\$t\" -gt 0 ] && new SET \$k \"\$v\" PX \$t NX >/dev/null && n=\$((n+1)); done; echo copied \$n"
gcloud run jobs execute valkey-copy-links --project=$P --region=$R --wait
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="valkey-copy-links"' \
  --project=$P --limit=5 --format='value(textPayload)'
gcloud run jobs delete valkey-copy-links --project=$P --region=$R --quiet
```

## 7. Verify

```bash
# The instance: IAM auth, TLS, Valkey 9.1.
gcloud memorystore instances describe overslash-prod-cache --location=$R --project=$P \
  --format='value(authorizationMode,transitEncryptionMode,engineVersion)'
# expect: IAM_AUTH  SERVER_AUTHENTICATION  VALKEY_9_1

# Cloud Run: no password anywhere, CA by secret ref.
gcloud run services describe overslash-prod-api --project=$P --region=$R --format=json \
  | jq '.spec.template.spec.containers[0].env[] | select(.name|test("^REDIS_"))'
gcloud run services describe overslash-prod-shortener --project=$P --region=$R --format=json \
  | jq '.spec.template.spec.containers[0].env[] | select(.name|test("^VALKEY_"))'

# The API connected. All three stores log once at boot, and none fell back.
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="overslash-prod-api"
  AND jsonPayload.message=~"(Rate limiter|Resolver cache|Session cache): using Redis/Valkey"' \
  --project=$P --freshness=30m --limit=6 --format='value(jsonPayload.message)'
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="overslash-prod-api"
  AND jsonPayload.message=~"(falling back|Redis unavailable|Invalid Valkey config|IAM token)"' \
  --project=$P --freshness=30m --limit=5

curl -fsS https://oversla.sh/ready
```

Capture the first three outputs for the CASA evidence pack (6.7.1,
`docs/compliance/casa/evidence-index.md`).

## Rollback

Until step 8, the old instance and its secrets are untouched. To go back, send traffic to
the last revisions from before step 5. They still carry `REDIS_PASSWORD` and the old URL:

```bash
gcloud run revisions list --service=overslash-prod-api --region=$R --project=$P --limit=5
gcloud run services update-traffic overslash-prod-api --region=$R --project=$P --to-revisions=<previous>=100
# same for overslash-prod-shortener
```

Then fix forward: the next apply moves traffic to a new revision again.

## 8. Clean up, after a week or so

Once nothing should need a rollback:

```bash
gcloud redis instances delete overslash-prod-valkey --region=$R --project=$P --quiet
gcloud secrets delete overslash-prod-valkey-auth --project=$P --quiet
gcloud secrets delete overslash-prod-valkey-server-ca --project=$P --quiet
```

Old Cloud Run revisions still reference those secrets. That's harmless while they serve
no traffic, but it means the rollback above stops working from here on.

## Later: replacing the instance without downtime

`cache_instance_name` defaults to `<base_prefix>-cache`. Setting it to anything else
builds a second instance next to the first. The instance, its IAM binding and its CA
secret are all `create_before_destroy`, and the secret is named after the instance, so
nothing collides. One apply then moves Cloud Run over and only afterwards deletes the old
instance. Use it for changes that force a replacement (`node_type` across families,
`authorization_mode`, `transit_encryption_mode`, the network):

```bash
TF_VAR_cache_instance_name=overslash-prod-cache-b make tofu-plan ENV=prod
TF_VAR_cache_instance_name=overslash-prod-cache-b make tofu-apply ENV=prod
```

It is an environment variable on purpose: `env/prod.tfvars` would override it (a
`-var-file` beats `TF_VAR_*`), so keep it out of there. The catch is that **every later
plan must set it too**, or the name reverts to the default and you swap back. Either
keep exporting it, or swap back to the default name at the next convenient moment.
The new keyspace starts empty either way; step 6 is how to carry links over.

The module's outputs wait on the new IAM binding, so Cloud Run only rolls once the
binding exists. IAM still takes a few minutes to *propagate*, though, and a revision that
boots inside that window can't authenticate. The API then serves on its in-memory
fallbacks until it restarts, and oversla-sh retries until it succeeds. After a rename
apply, run the fallback log query from step 7. If it matches, roll a fresh revision:
`gcloud run services update overslash-prod-api --region=$R --project=$P --update-labels=rollout=$(date +%s)`.

This path has been planned against a simulated prod state, but no rename has been
applied yet. Read the first rename plan carefully: expect `+/-` (create before destroy)
on the instance, the IAM member, the secret and its version, and `~` on both Cloud Run
services.

Engine upgrades (`valkey_engine_version`) happen in place and need none of this.
Downgrades are not possible.
