# BI: BigQuery federation over the `bi` schema

Business questions ("which orgs exist and who owns them?") are answered in
BigQuery and Looker Studio, never by giving people a prod DB shell.

```
Cloud SQL (private IP)
  └─ schema bi (views, migration 126)   ← read as login user `bi` (role bi_reader)
       └─ BigQuery connection <prefix>-pg
            └─ dataset overslash_bi (EXTERNAL_QUERY views)  ← Looker Studio / BQ console
```

- **Live, not copied.** Each BigQuery view runs an `EXTERNAL_QUERY` against
  the instance at query time. Nothing is replicated, so there is no pipeline
  to keep healthy and no stale copy of personal data. If analytics ever gets
  heavy enough to load the primary, move to Datastream replication into
  BigQuery and keep the same `bi` views as its source.
- **Curated.** `bi_reader` has no grant on `public`. The views project only
  non-sensitive columns, so secrets, tokens and encrypted blobs can't reach BI.
- **Terraform-gated.** The `infra/modules/bi` module is controlled by `enable_bi`,
  which is on in prod. Access is IAM: project owners, plus `bi_viewers`.

## Views

| View | One row per | Useful for |
|------|-------------|------------|
| `org_summary` | org | name, creator, admin emails, user and agent counts, last activity |
| `orgs` | org | plan, personal vs team, trial end, creator |
| `org_members` | user identity | membership, admin flag, last activity, archived |

"Owner" means the org's admins (`is_org_admin`). The creator is listed
separately, because a creator can leave the org and admins can change.

## Enabling in an environment

1. Deploy the API so migration 126 has run.
2. `make tofu-apply` for that environment, with `enable_bi = true`.
   Nothing applies terraform automatically.
3. Wait for the next API boot (any deploy or restart). After migrations,
   `overslash_db::bi::reconcile_bi_user` grants `bi_reader` to `bi`. It also
   revokes `cloudsqlsuperuser`, which Cloud SQL gives every user created
   through its API, so `bi` ends up holding `bi_reader` and nothing else.
   It is idempotent and never fails the boot; problems show up as a
   `bi user reconcile failed` warning in the API logs. To skip the wait, run
   the same statements by hand:
   ```bash
   bin/db-shell.sh prod
   GRANT bi_reader TO bi;
   REVOKE cloudsqlsuperuser FROM bi;
   ```
   Then confirm with `\du bi`: the only role listed should be `bi_reader`.
4. Check it in the BigQuery console:
   `SELECT * FROM overslash_bi.org_summary ORDER BY created_at`.

## Adding a view

1. Add a migration with `CREATE VIEW bi.<name> AS …`. The migration 126 default
   privileges grant `bi_reader` SELECT on it automatically. Select only
   columns that are safe to show in a dashboard.
2. Add `<name>` to `local.views` in `infra/modules/bi/main.tf`, then apply.
3. Extend `crates/overslash-api/tests/bi_views.rs` if the view has logic.

## Looker Studio

In Looker Studio, create a data source with the BigQuery connector, pick
project `overslash` → `overslash_bi` → a view, and build the report on it. The
viewer's own credentials are used, so they need BigQuery access (step 2's IAM).
