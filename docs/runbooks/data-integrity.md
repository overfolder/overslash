# Data integrity sweep

The `[P1] <prefix> Data Integrity Violation` alert means the database holds a
stored reference that crosses a user or org boundary.

## What it is

The binding policies (D122) refuse a cross-user or cross-org reference when it
is written and again when it is read. Some rows never went through them:

- rows written before the fix (migration 133 left cross-user bindings in place
  with a `RAISE NOTICE`),
- rows edited by hand,
- rows written by a path nobody listed.

The **integrity sweep** finds those rows.

- **Where it runs.** The metrics-exporter Cloud Run Job runs it every 5 minutes
  (`infra/modules/metrics-exporter-job`).
- **How it checks.** Each invariant is one read-only `SELECT` in
  [`crates/overslash-db/src/integrity/`](../../crates/overslash-db/src/integrity/).
  A query returns only the offending rows. Its columns are `org_id`,
  `subject_table`, `subject_id` and `detail`; `detail` holds ids, a slot key or
  a secret *path*, never a secret value.
- **What it emits.**
  - Gauge `custom.googleapis.com/overslash/business/integrity_violations{invariant=…}`,
    one point per invariant on every tick, zeros included.
  - One WARN log line `integrity violation` per offending row.
- **When the alert fires.**
  - Any point is above 0.
  - Or the series has been absent for 30 minutes. That means the sweep itself
    failed: look for `Integrity sweep failed` in the job logs.
- **Business dashboard.** The `Integrity Violations by Invariant` tile plots the
  same gauge.
- **Cost.** Every query reads the small per-org configuration tables through
  primary keys and owner indexes. Approval checks read pending rows only. Each
  statement has a 30s `statement_timeout`.

## Invariants

| `invariant` | A row breaks it when… | Guards |
|---|---|---|
| `binding_unqualified` | a `secret_name` or `credentials` value is neither `org/<name>` nor `<user identity id>/<name>` | D119, migration 133 |
| `binding_namespace_outside_org` | a `<uuid>/<name>` binding names something other than a user of the instance's own org: another org's user, an agent, or a dangling id | D119 |
| `binding_foreign_user_vault` | a user-level instance is bound into a colleague's vault. This is the Reveni julia→angel shape. The read rule makes it run unbound | D119, D122 |
| `pin_on_org_instance` | an org-level instance has a pinned `connection_id` | #723 |
| `pin_cross_org` | a user-level instance is pinned to a connection in another org | #723 |
| `pin_not_owner` | a user-level instance is pinned to a same-org connection that is neither the owner's nor one of the owner's agents' | #723, D122 |
| `byoc_cross_org` | a connection uses a BYOC OAuth client from another org | D122 |
| `byoc_provider_mismatch` | a connection's BYOC client is for a different provider | D122 |
| `byoc_not_owner` | a connection's BYOC client does not belong to the connection's ceiling user | D122 |
| `secret_owner_not_user` | a live secret is in an agent's vault. Vaults are per user and per org, and migration 133 could not re-home agents that have no `owner_id` | D119 |
| `owner_cross_org` | an instance, connection, BYOC client, secret, template or permission rule is owned by an identity of another org, or an identity's `parent_id`/`owner_id` points into another org. `subject_table` says which | tenancy |
| `template_cross_org` | an instance's `template_id` is a template in another org | D122 |
| `template_cross_owner` | a `user`-tier instance records another user's template, or an `org`-tier one records a user template | D122 |
| `approval_cross_org` | a pending approval's requester or current resolver is in another org | #737 |
| `approval_resolver_outside_chain` | a pending approval's resolver is neither the requester nor one of its ancestors. Approvals only bubble upward, and `may_read_approval` would give a stranger the payload | #737 |

**Not swept:** the check that a pinned connection's provider matches the
template's OAuth provider. The provider is not stored in SQL. It lives in the
template YAML or the layered DB template, and resolving it needs
`template_resolve`. Check it by hand when a `pin_*` alert fires, or with
`GET /v1/services/{id}` (the pin shows as unusable). It is tracked in TODO.md.

## Drill down

1. **Logs.** In Cloud Logging, run this query on the metrics-exporter job:

   ```
   resource.type="cloud_run_job"
   jsonPayload.fields.message="integrity violation"
   jsonPayload.fields.invariant="<invariant>"
   ```

   Each entry carries `org_id`, `subject_table`, `subject_id` and `detail`.
   The exact field path depends on the tracing JSON layout; search for the
   message text if the filter comes back empty.
2. **SQL.** Run the same file that fired, read-only. Use the cloud-sql-proxy
   with `--token` (see the dev DB access notes; prod needs an operator with
   access):

   ```sh
   psql "$DATABASE_URL" -X -f crates/overslash-db/src/integrity/<invariant>.sql
   ```

   The column aliases carry sqlx's `!` nullability marker (`"org_id!"`).
   That is cosmetic.
3. **Context.** Look up the org (`SELECT name, slug FROM orgs WHERE id = …`)
   and the owner (`SELECT name, email, kind FROM identities WHERE id = …`)
   before you contact anyone.

## Remediate

Prefer the product path. It goes through the same binding policies that should
have refused the row in the first place.

- **`binding_*`**
  - The instance owner opens the service in the dashboard (Services → the
    instance → credentials) and rebinds each slot to a secret in their own
    vault or the org vault. Through the API, that is
    `PUT /v1/services/{id}/manage` with `credentials` (or `secret_name`).
  - `BindingWriter` keeps an *unchanged* stored value verbatim. So the slot
    must be **set to a new path** or cleared (`"secret_name": null`); a no-op
    save leaves it in place.
  - If the owner needs the value itself, they create it in their own vault.
    Nobody copies a colleague's secret.
- **`pin_*`**
  - Unpin in the dashboard, or call `PUT /v1/services/{id}/manage` with
    `{"connection_id": null}`. If `use_default_connection` is set, the instance
    falls back to the owner's default connection for the provider.
  - For an org-level instance (`pin_on_org_instance`) the only fix is to unpin.
- **`byoc_*`**: the connection owner reconnects with their own (or the org's)
  BYOC client, then deletes the old connection (`DELETE /v1/connections/{id}`).
- **`secret_owner_not_user`**
  - If the agent still exists, re-home the secret to the agent's owner: the
    owner re-creates it in their vault, and you delete the agent-owned row.
  - Otherwise delete it.
- **`owner_cross_org`, `template_cross_*`**: these are not reachable through
  the API at all, so treat them as an incident.
  - Find out how the row was written (audit log, recent manual SQL).
  - Delete the instance and re-create it from the right tier.
  - Fix any identity chain by hand.
- **`approval_*`**: deny the approval (`POST /v1/approvals/{id}/resolve`), or
  let it expire. Then find the path that assigned the resolver.

Use a raw SQL fix only as a last resort. When you do, double-key every
statement on `org_id` as well as `id`, run it inside a transaction, and re-run
the invariant file before you commit.

A fixed row clears on the next tick. The alert auto-closes once every series is
back to 0.

## Rollout and changes

Terraform is never auto-applied. The exporter image, however, deploys itself:
the `<prefix>-metrics-exporter-deploy` Cloud Build trigger fires on a push to
the deploy branch (`overslash-dev-metrics-exporter-deploy` for dev).

1. Merge. Wait for the exporter build, then for one scheduler tick (≤ 5 min).
2. Confirm the descriptor exists:

   ```sh
   gcloud monitoring metrics-descriptors list --project=<project> \
     --filter='metric.type = "custom.googleapis.com/overslash/business/integrity_violations"'
   ```

   Cloud Monitoring rejects an alert policy on a custom metric that has never
   been written. That is why the alert is gated.
3. Set `integrity_alert_enabled = true` in `infra/env/<env>.tfvars`.
4. Run `make tofu-plan ENV=<env>`, review it (expect one new
   `google_monitoring_alert_policy.data_integrity_violation` and the
   re-created `business` dashboard), then run `make tofu-apply ENV=<env>`.
   Do dev first, then prod.

**Adding an invariant:**

1. Add `src/integrity/<label>.sql` returning the four columns.
2. Add an `Invariant` variant.
3. Add a test in `crates/overslash-api/tests/integrity_invariants.rs` that plants
   one violation and calls `assert_only`. That test also proves the new label
   does not double-count.
4. Run `make sqlx-prepare`.

Labels are metric label values, so renaming one breaks the alert's history.
