-- One row per org. Runs in Postgres as `bi`; see org_summary.sql.
SELECT o.id::text AS id,
       o.name,
       o.slug,
       o.is_personal,
       o.plan,
       o.trial_ends_at,
       o.created_at,
       cu.email        AS creator_email,
       cu.display_name AS creator_name
FROM orgs o
LEFT JOIN users cu ON cu.id = o.creator_user_id
