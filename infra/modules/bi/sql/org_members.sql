-- One row per user identity (agents excluded). Runs in Postgres as `bi`;
-- see org_summary.sql.
SELECT o.id::text AS org_id,
       o.name     AS org_name,
       i.id::text AS identity_id,
       i.name,
       i.email,
       i.is_org_admin,
       i.created_at,
       i.last_active_at,
       i.archived_at
FROM identities i
JOIN orgs o ON o.id = i.org_id
WHERE i.kind = 'user'
