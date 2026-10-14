# Memorystore AUTH + in-transit encryption — applying it

> **Superseded.** This describes the Memorystore *for Redis* instance with an AUTH string.
> The module now builds Memorystore for Valkey with IAM auth; the cutover is
> [memorystore-valkey.md](memorystore-valkey.md). Kept for the history of the CASA 6.7.1
> fix and for the old instance until it is deleted.

`infra/modules/memorystore/main.tf` now sets, on `google_redis_instance.valkey`:

| Setting | Value | CASA |
|---|---|---|
| `auth_enabled` | `true` | 6.7.1 |
| `transit_encryption_mode` | `SERVER_AUTHENTICATION` (TLS, port **6378**) | 6.7.1 (and 4.1.1 in spirit) |

and publishes the two values clients need through Secret Manager:

| Secret | Contents | Read by |
|---|---|---|
| `overslash-<env>-valkey-auth` | the instance AUTH string | API as `REDIS_PASSWORD`, oversla-sh as `VALKEY_PASSWORD` |
| `overslash-<env>-valkey-server-ca` | every server CA the instance serves, PEM, concatenated | API as `REDIS_CA_CERT`, oversla-sh as `VALKEY_CA_CERT` |

Both arrive in Cloud Run through `secret_key_ref`. Neither appears as a plaintext env var.
The URLs turn into `rediss://<ip>:6378`. Clients trust **only** the pinned CA, not the
system store, and they still check the server certificate against the host they dial.
The client code is `crates/overslash-api/src/services/valkey.rs` and
`crates/oversla-sh/src/storage.rs`.

Only prod is affected: dev has `enable_valkey = false`, so `module.memorystore` has
`count = 0` there and the dev plan shows no change.

Infra is never auto-applied. This page is the operator's half of the change.

## What the apply does, and why it is disruptive

**`transit_encryption_mode` can only be set when an instance is created.** Google does not
allow turning TLS on in place, so OpenTofu plans a **replacement** of
`google_redis_instance.valkey`, shown as `-/+ … must be replaced`. The instance name is
fixed, so the replacement is destroy-then-create, not create-before-destroy. That means:

- **Downtime of a few minutes**, roughly the time to provision a `BASIC` instance. Cloud
  Run revisions are updated in the same apply, once the new instance and its secrets exist.
- **The keyspace starts empty.** `BASIC` has no persistence. For each key family:
  - API rate-limit counters, resolver cache and session-check cache rebuild on their own.
    The rate limiter fails open, the resolver cache resolves live on a miss, and the
    session gate falls back to Postgres. Users see no errors from this.
  - **oversla.sh short links are lost.** Each link has a TTL of at most 7 days
    (`MAX_TTL_SECS`), and approval and download links in flight will 404. To keep them,
    run the export/import in step 4 below. Otherwise schedule the apply when a 7-day loss
    of short links is acceptable.
- **The IP changes.** Nothing hard-codes it: `REDIS_URL` and `VALKEY_URL` are built from
  the module outputs in the same apply.

`auth_enabled` alone can be flipped in place. The replacement comes from TLS.

### Behaviour while the instance is gone

- **API**: stays up. Each Redis-backed store falls back at boot if Valkey is unreachable:
  the rate limiter and resolver cache go in-memory, and the session cache is disabled. At
  request time, every Redis-backed path fails open. Instances that booted during the gap
  stay on their fallbacks until the next revision or restart, which the apply's own
  revision rollout provides.
- **oversla.sh**: **down.** It pings Valkey at boot and exits if that fails, by design.
  Cloud Run keeps retrying until the new instance answers.

## Before applying

1. **Deploy code that understands the new variables first.** The API and oversla-sh images
   must contain this PR before the apply. An old binary given `rediss://` cannot connect:
   the API would silently fall back to in-memory, and oversla-sh would crash-loop. The new
   code works without the new variables, so it is safe to ship ahead of the infra change.
   Check that the running images are at or after the merge commit:

   ```bash
   gcloud run services describe overslash-prod-api --region=europe-west1 --project=overslash \
     --format='value(spec.template.spec.containers[0].image)'
   gcloud run services describe overslash-prod-shortener --region=europe-west1 --project=overslash \
     --format='value(spec.template.spec.containers[0].image)'
   ```

   oversla-sh is deployed by hand: `make shortener-deploy ENV=prod`.

2. **Pre-flight: confirm a Memorystore TLS certificate verifies against its IP.** The
   clients connect by IP and rustls requires the server certificate to name that IP. Google
   does not document the certificate's SANs, and the IP check cannot be skipped
   without disabling verification entirely, which this change deliberately does not do.
   Prove it on a throwaway instance before touching prod. It costs a few cents and leaves
   prod untouched:

   ```bash
   P=overslash R=europe-west1 NET=overslash-prod-vpc   # modules/networking: ${base_prefix}-vpc
   gcloud redis instances create valkey-tls-preflight --project=$P --region=$R \
     --tier=basic --size=1 --redis-version=redis_7_2 --network=$NET \
     --transit-encryption-mode=server-authentication --enable-auth
   IP=$(gcloud redis instances describe valkey-tls-preflight --project=$P --region=$R --format='value(host)')
   gcloud redis instances describe valkey-tls-preflight --project=$P --region=$R \
     --format='value(serverCaCerts[0].cert)' > /tmp/preflight-ca.pem
   gcloud secrets create valkey-tls-preflight-ca --project=$P --data-file=/tmp/preflight-ca.pem
   # A one-off job on the same VPC connector the services use.
   gcloud run jobs create valkey-tls-preflight --project=$P --region=$R \
     --image=alpine:3.20 --vpc-connector=overslash-prod-vpc-conn \
     --set-secrets=/ca/ca.pem=valkey-tls-preflight-ca:latest \
     --command=sh --args=-c,"apk add -q openssl && openssl s_client -connect $IP:6378 -CAfile /ca/ca.pem -verify_ip $IP -verify_return_error </dev/null 2>&1 | grep -E 'Verify return code|verify error'"
   gcloud run jobs execute valkey-tls-preflight --project=$P --region=$R --wait
   gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="valkey-tls-preflight"' \
     --project=$P --limit=20 --format='value(textPayload)'
   ```

   **Expect `Verify return code: 0 (ok)`.** Then clean up:

   ```bash
   gcloud run jobs delete valkey-tls-preflight --project=$P --region=$R --quiet
   gcloud secrets delete valkey-tls-preflight-ca --project=$P --quiet
   gcloud redis instances delete valkey-tls-preflight --project=$P --region=$R --quiet
   ```

   If it reports `IP address mismatch` instead, **stop**. The clients would refuse the
   real instance the same way: the API would run on fallbacks and oversla-sh would be down.
   Comment on the tracking issue. The fix is a client-side verifier that checks the chain
   against the pinned per-instance CA without matching the IP, which needs a code change.

3. **Plan, read-only:**

   ```bash
   make tofu-plan ENV=prod
   ```

   Expect exactly these. Anything else is unrelated drift, so stop and look:
   - `module.memorystore[0].google_redis_instance.valkey` **must be replaced**,
     `transit_encryption_mode` forces replacement, `auth_enabled` `false -> true`;
   - `+` 2 × `google_secret_manager_secret` and 2 × `google_secret_manager_secret_version`
     (`overslash-prod-valkey-auth`, `overslash-prod-valkey-server-ca`);
   - `~` `module.cloud_run.google_cloud_run_v2_service.api`: `REDIS_URL` becomes
     `rediss://…:6378` (known after apply), plus `REDIS_PASSWORD` and `REDIS_CA_CERT` as
     `secret_key_ref`;
   - `~` `module.cloud_run_shortener[0].google_cloud_run_v2_service.shortener`: same with
     `VALKEY_*`.

4. **Optional: keep oversla.sh links.** `BASIC` instances support RDB export and import
   through GCS. Run the export immediately before the apply and the import immediately
   after. Links created between the two are lost.

   ```bash
   B=gs://<scratch-bucket>   # grant the instance's persistenceIamIdentity objectAdmin on it; delete after
   gcloud redis instances export $B/valkey.rdb overslash-prod-valkey --region=europe-west1 --project=overslash
   # … apply (next section) …
   gcloud redis instances import $B/valkey.rdb overslash-prod-valkey --region=europe-west1 --project=overslash
   ```

   An import **flushes and restarts** the new instance, which causes a second short blip.
   The dump also carries cache entries, which are ciphertext with TTLs and harmless to
   restore. Delete the RDB object afterwards: the resolver-cache values are encrypted, but
   the dump is still a copy of the keyspace.

## Applying

```bash
make tofu-apply ENV=prod
```

The replacement takes a few minutes. Apply order follows the references:
instance → secret versions → Cloud Run revisions.

## Verifying

```bash
P=overslash R=europe-west1
# 1. The instance: AUTH on, TLS on, port 6378.
gcloud redis instances describe overslash-prod-valkey --project=$P --region=$R \
  --format='value(authEnabled,transitEncryptionMode,port)'
# expect: True  SERVER_AUTHENTICATION  6378

# 2. The secrets exist and have a version. Prints metadata only, never the payload.
gcloud secrets versions list overslash-prod-valkey-auth --project=$P --limit=1
gcloud secrets versions list overslash-prod-valkey-server-ca --project=$P --limit=1

# 3. Cloud Run wires them as secret refs, not values.
gcloud run services describe overslash-prod-api --project=$P --region=$R --format=json \
  | jq '.spec.template.spec.containers[0].env[] | select(.name|test("^REDIS_"))'
gcloud run services describe overslash-prod-shortener --project=$P --region=$R --format=json \
  | jq '.spec.template.spec.containers[0].env[] | select(.name|test("^VALKEY_"))'
# expect REDIS_URL / VALKEY_URL = rediss://<ip>:6378 and the other two as valueFrom.secretKeyRef

# 4. The API actually connected over TLS with AUTH. All three stores log once at boot.
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="overslash-prod-api"
  AND jsonPayload.message=~"(Rate limiter|Resolver cache|Session cache): using Redis/Valkey"' \
  --project=$P --freshness=30m --limit=6 --format='value(jsonPayload.message)'
# and no fallbacks:
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="overslash-prod-api"
  AND jsonPayload.message=~"(falling back|Redis unavailable|Invalid Valkey config)"' \
  --project=$P --freshness=30m --limit=5

# 5. oversla.sh is serving: /ready pings Valkey.
curl -fsS https://oversla.sh/ready
```

A plaintext client on the VPC is now refused, because the port changed and the instance
speaks only TLS. A TLS client without the AUTH string gets `NOAUTH`. Capture the outputs
of steps 1–3 for the evidence pack (`docs/compliance/casa/evidence-index.md`, 6.7.1).

## Rollback

There is no cheap rollback: turning TLS off is another replacement. If clients cannot
connect after the apply, the API keeps serving on its fallbacks, so only oversla.sh is
down. In that case:

- **Wrong or missing secret:** fix the version and redeploy a revision
  (`gcloud run services update … --update-labels=rollout=$(date +%s)`).
- **Certificate verification fails** (`invalid peer certificate` in the logs): this is the
  failure step 2 exists to catch. Revert the two lines in
  `infra/modules/memorystore/main.tf` and the shortener's `rediss://`, then apply. That
  replaces the instance again, back to plaintext.

## Later: CA rotation and AUTH string rotation

- **Server CA.** Each CA is valid for 10 years. Memorystore adds a new CA five years in,
  and serves the old and new side by side. `server_ca_certs` lists both, so a
  `make tofu-apply ENV=prod` writes a new secret version holding both. The next Cloud Run
  revision picks it up (`version = "latest"`). Server *certificates* rotate every 180 days
  under the same CA, which needs no action. Clients see a reconnect, and
  `ConnectionManager` retries on its own.
- **AUTH string.** `gcloud redis instances update … --enable-auth` does not rotate it.
  Rotation means disabling and re-enabling AUTH, which issues a new string and drops
  every client until it has the new one. Re-apply to refresh the secret version, then
  roll both services.
