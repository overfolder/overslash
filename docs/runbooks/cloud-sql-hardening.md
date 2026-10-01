# Cloud SQL hardening — applying it

`infra/modules/cloud-sql/main.tf` sets, on both environments:

| Setting | Value | CASA |
|---|---|---|
| `ip_configuration.ssl_mode` | `ENCRYPTED_ONLY` | 4.1.1 |
| `deletion_protection` (Terraform) + `settings.deletion_protection_enabled` (Cloud SQL API) | `true` | — |
| `log_connections`, `log_disconnections` | `on` | 6.7.1 |
| `cloudsql.enable_pgaudit` | `on` | 6.7.1 |
| `pgaudit.log` | `ddl,role` | 6.7.1 |
| `cloudsql.pgaudit_mask_literals` | `on` | 6.7.1 |

Infra is never auto-applied. This page is the human half.

## Who connects, and why `ENCRYPTED_ONLY` breaks none of them

`ENCRYPTED_ONLY` refuses plaintext on **direct** connections to the instance IP. The Cloud
SQL Auth Proxy and the language connectors are always TLS and are admitted whatever the
mode. Every client we run goes through one:

| Client | Path |
|---|---|
| API (Cloud Run), including migrations — they run in-process at boot (`overslash_db::MIGRATOR`) | `/cloudsql` volume → the managed Auth Proxy; `entrypoint.sh` builds `?host=/cloudsql/<connection>` |
| `overslash-metrics-exporter` job | same `/cloudsql` volume (`infra/modules/metrics-exporter-job`) |
| BigQuery federation, prod only (`infra/modules/bi`) | `google_bigquery_connection` of type `cloud_sql` — Google's managed path, authorised by the connection's own service account holding `roles/cloudsql.client`. Google's federation docs list no SSL-mode limitation, but they don't say so outright either, which is why the prod apply ends with a BI smoke query |
| Humans | `bin/db-shell.sh` → local `cloud-sql-proxy`. psql's `sslmode=disable` there is the loopback hop to the proxy; the proxy → instance hop is TLS |

Nothing connects to an instance IP directly. Prod has no public IP; dev has one with zero
authorized networks. If someone does add a temporary authorized network on dev, `psql` and
sqlx default to `sslmode=prefer` and negotiate TLS, so that still works — only an explicit
`sslmode=disable` is refused.

## Before applying

1. **Pick a quiet window for prod.** `cloudsql.enable_pgaudit` restarts the instance. Expect
   one to two minutes of `/ready` failing and 5xx on the API. Nothing else in the change
   restarts it; `ssl_mode` does not.
2. **Check for plaintext connections that would be cut** (read-only):

   ```bash
   bin/db-shell.sh prod -c "select a.usename, a.application_name, a.client_addr, s.ssl
     from pg_stat_activity a join pg_stat_ssl s using (pid)
     where a.backend_type = 'client backend' order by s.ssl, a.usename;"
   ```

   Every row should be `ssl = t` (Auth Proxy connections show as TLS server-side). A row
   with `ssl = f` is a client this change will disconnect — find it first.

## Apply — dev, then prod

The full plan may carry unrelated drift, since nothing applies infra automatically. Read it:
if the only change you want is this one, target it.

```bash
make tofu-init
make tofu-plan ENV=dev
# Expect: module.cloud_sql.google_sql_database_instance.db updated in-place —
#   deletion_protection false -> true, settings.deletion_protection_enabled false -> true,
#   ip_configuration.ssl_mode + ENCRYPTED_ONLY, five database_flags added.
# If other resources show up and you don't want them now:
#   cd infra && tofu workspace select dev && \
#   tofu plan -var-file=env/dev.tfvars -target=module.cloud_sql -out=dev.tfplan
make tofu-apply ENV=dev
```

Then, once per instance, create the extension (pgAudit logs nothing without it):

```bash
bin/db-shell.sh dev -c 'CREATE EXTENSION IF NOT EXISTS pgaudit;'
```

Verify:

```bash
gcloud sql instances describe overslash-dev-db --project overslash-dev \
  --format='yaml(settings.ipConfiguration.sslMode,settings.deletionProtectionEnabled,settings.databaseFlags)'
curl -fsS https://api.dev.overslash.com/ready
bin/db-shell.sh dev -c "select extname, extversion from pg_extension where extname = 'pgaudit';"
```

Repeat with `ENV=prod` (`make tofu-apply ENV=prod` asks you to type `prod`), the
`CREATE EXTENSION` against `prod`, and in addition confirm BI still reads — run any view in
the `overslash_bi` dataset from the BigQuery console, or:

```bash
bq --project_id=overslash query --use_legacy_sql=false \
  'SELECT * FROM EXTERNAL_QUERY("overslash.europe-west1.overslash-prod-pg", "SELECT 1")'
```

## After

- pgAudit writes Cloud Logging **Data Access** audit logs. Both projects currently return
  `auditConfigs: NONE`, so until the TODO.md §1.6 audit-config item lands, pgAudit records
  nothing you can read. The connection logs go to `cloudsql.googleapis.com/postgres.log`
  and are visible now.
- Recommender re-evaluates on its own schedule. After a day or two, re-run the scan in
  [gcp-posture.md](../compliance/casa/gcp-posture.md): `REQUIRE_SSL` and
  `ENABLE_DATABASE_AUDITING` should be gone. The two password-policy recommendations will
  remain — they are declined on purpose; see that page.

## Deleting an instance now

Deliberately two steps: set both `deletion_protection` and `deletion_protection_enabled`
to `false`, apply, then destroy or `gcloud sql instances delete`.

## Rollback

Revert the module change and apply. To relax only TLS, set `ssl_mode =
"ALLOW_UNENCRYPTED_AND_ENCRYPTED"`. Turning `cloudsql.enable_pgaudit` off restarts the
instance again.
