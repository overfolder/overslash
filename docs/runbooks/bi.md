# BI: BigQuery federation over prod Postgres

Business questions ("which orgs exist and who owns them?") are answered in
BigQuery and Looker Studio, never by giving people a prod DB shell.

```
infra/modules/bi/sql/<name>.sql ──► BigQuery view overslash_bi.<name>
                                      = EXTERNAL_QUERY(<prefix>-pg, <that SQL>)
                                            │ runs live, as Postgres role `bi`
                                            ▼
Cloud SQL (private IP): `bi` may SELECT only overslash_db::bi::READABLE_COLUMNS
```

- **Queries are terraform.** Each file in `infra/modules/bi/sql/` becomes a
  BigQuery view. Changing a report means editing SQL and running `tofu
  apply`. No migration and no app release.
- **The boundary is Rust.** The API creates the `bi` login role at boot and
  sets its grants to exactly `READABLE_COLUMNS` (`crates/overslash-db/src/bi.rs`):
  identity, naming, ownership and activity columns, nothing secret or
  encrypted. `bi` belongs to no role, and in particular not to
  `cloudsqlsuperuser`, which every `google_sql_user` joins and the app
  couldn't revoke.
- **Nothing in the app schema depends on BI.** There are no views, schema or
  migration, so app migrations can never be blocked by a BI object, and
  dropping a column simply drops its grant.
- **CI runs every query.** `tests/bi_views.rs` executes each `sql/*.sql` as
  `bi` against the migrated schema. A renamed column, or a query reaching past
  the allow-list, fails the build rather than a dashboard.
- **Live, not copied.** Nothing is replicated, so there is no pipeline to keep
  healthy and no stale copy of personal data. If analytics ever gets heavy
  enough to load the primary, move to Datastream replication into BigQuery.

## Queries

| View | One row per | Useful for |
|------|-------------|------------|
| `org_summary` | org | name, creator, admin emails, user and agent counts, last activity |
| `orgs` | org | plan, personal vs team, trial end, creator |
| `org_members` | user identity | membership, admin flag, last activity, archived |

"Owner" means the org's admins (`is_org_admin`). The creator is listed
separately, because a creator can leave the org and admins can change. Cast
UUIDs to `text`, since BigQuery federation has no UUID type.

## Enabling in an environment

1. Set `enable_bi = true` in that environment's tfvars and run `make tofu-apply`.
   Nothing applies terraform automatically. The apply creates the password
   secret, the BigQuery connection and the views, and mounts the password into
   Cloud Run as `OVERSLASH_BI_DB_PASSWORD`, which rolls out a new revision.
2. That revision's boot runs `overslash_db::bi::reconcile_bi_user`: it creates
   `bi`, sets its password, and replaces its grants with the allow-list. This
   happens on every boot, so rotating the secret or changing the allow-list
   only takes a deploy. Failures are logged as `bi user reconcile failed`.
3. Check it in the BigQuery console:
   `SELECT * FROM overslash_bi.org_summary ORDER BY created_at`.

## Adding a query

1. Add `infra/modules/bi/sql/<name>.sql`. Name columns explicitly (no `*`)
   and cast UUIDs to text.
2. If it reads a column that isn't in `READABLE_COLUMNS`, add the column
   there. That is a code change reviewed like any other, and it takes effect
   on the next API deploy.
3. `make test` runs it as `bi`, then `tofu apply` publishes it.

## Looker Studio

In Looker Studio, create a data source with the BigQuery connector, pick
project `overslash` → `overslash_bi` → a view, and build the report on it. The
viewer's own credentials are used, so they need BigQuery access: project
owner, or listed in `bi_viewers`.
