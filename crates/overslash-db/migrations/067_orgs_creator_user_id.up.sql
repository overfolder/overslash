-- Track the original creator of each org. Needed so the `membership.removed`
-- audit event can flag departures by the founder (the org's creator leaving
-- is a notable state change distinct from a routine member exit).
--
-- Nullable: orgs created before this migration have no recorded creator
-- unless their `org.created` audit row points to an identity with a
-- resolved `user_id`. The best-effort backfill below populates what we
-- can; anonymous-creator paths (no session at POST /v1/orgs) intentionally
-- stay NULL.
--
-- ON DELETE SET NULL: if the user row is hard-deleted (GDPR, manual
-- cleanup), the org keeps its history without leaving a dangling FK.

ALTER TABLE orgs
    ADD COLUMN creator_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

UPDATE orgs o
SET creator_user_id = sub.user_id
FROM (
    SELECT DISTINCT ON (a.org_id)
           a.org_id,
           i.user_id
    FROM   audit_log a
    JOIN   identities i ON i.id = a.identity_id
    WHERE  a.action = 'org.created'
      AND  i.user_id IS NOT NULL
    ORDER BY a.org_id, a.created_at ASC
) sub
WHERE o.id = sub.org_id AND o.creator_user_id IS NULL;
