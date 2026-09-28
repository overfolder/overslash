-- Curated BI surface (see docs/runbooks/bi.md).
--
-- BI tooling (BigQuery federation → Looker Studio) never reads `public`. It
-- reads only these views, through the NOLOGIN role `bi_reader`, which the
-- terraform-managed `bi` login user is granted once per environment. The
-- views are the stable contract: they project only non-sensitive columns, so
-- secrets, tokens and encrypted blobs can never reach a dashboard, and a
-- rename in `public` breaks a migration here instead of a report downstream.
--
-- Views run with their owner's rights (no security_invoker), so `bi_reader`
-- needs no grant on any `public` table.
CREATE SCHEMA bi;

CREATE VIEW bi.orgs AS
SELECT o.id,
       o.name,
       o.slug,
       o.is_personal,
       o.plan,
       o.trial_ends_at,
       o.created_at,
       cu.email        AS creator_email,
       cu.display_name AS creator_name
FROM orgs o
LEFT JOIN users cu ON cu.id = o.creator_user_id;

CREATE VIEW bi.org_members AS
SELECT o.id   AS org_id,
       o.name AS org_name,
       i.id   AS identity_id,
       i.name,
       i.email,
       i.is_org_admin,
       i.created_at,
       i.last_active_at,
       i.archived_at
FROM identities i
JOIN orgs o ON o.id = i.org_id
WHERE i.kind = 'user';

-- One row per org: who owns it (its admins) and how alive it is.
CREATE VIEW bi.org_summary AS
SELECT o.id,
       o.name,
       o.slug,
       o.is_personal,
       o.plan,
       o.created_at,
       cu.email AS creator_email,
       string_agg(i.email, ', ' ORDER BY i.email)
           FILTER (WHERE i.kind = 'user' AND i.is_org_admin) AS admin_emails,
       count(i.id) FILTER (WHERE i.kind = 'user')             AS user_count,
       count(i.id) FILTER (WHERE i.kind = 'agent')            AS agent_count,
       max(i.last_active_at)                                  AS last_active_at
FROM orgs o
LEFT JOIN users cu ON cu.id = o.creator_user_id
LEFT JOIN identities i ON i.org_id = o.id AND i.archived_at IS NULL
GROUP BY o.id, cu.email;

-- Roles are cluster-wide, so the role may already exist (another database on
-- the same instance, or a concurrent test-template migrate). A deployment
-- whose migrating user lacks CREATEROLE still migrates; it just gets no
-- `bi_reader` until an operator creates it and re-runs the grants below.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bi_reader') THEN
        CREATE ROLE bi_reader NOLOGIN;
    END IF;
EXCEPTION
    WHEN duplicate_object THEN NULL;
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'bi_reader not created (no CREATEROLE); BI stays disabled';
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bi_reader') THEN
        GRANT USAGE ON SCHEMA bi TO bi_reader;
        GRANT SELECT ON ALL TABLES IN SCHEMA bi TO bi_reader;
        ALTER DEFAULT PRIVILEGES IN SCHEMA bi GRANT SELECT ON TABLES TO bi_reader;
    END IF;
END
$$;
