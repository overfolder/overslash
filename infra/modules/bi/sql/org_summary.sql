-- One row per org: who owns it (its admins) and how alive it is.
-- Runs in Postgres as `bi` (column grants: overslash_db::bi::READABLE_COLUMNS).
-- UUIDs are cast to text: BigQuery federation has no UUID type.
SELECT o.id::text AS id,
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
GROUP BY o.id, o.name, o.slug, o.is_personal, o.plan, o.created_at, cu.email
