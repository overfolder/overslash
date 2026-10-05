-- Invariant approval_resolver_outside_chain (#737, approval bubbling).
-- A pending same-org approval whose current resolver is neither the
-- requester nor one of its ancestors (parent_id chain). Approvals start at
-- the gap level and only bubble upward (repos::approval::update_resolver), and
-- may_read_approval lets the resolver's ancestors read the request — so a
-- resolver outside the chain hands someone else's payload to a stranger.
WITH RECURSIVE pending AS (
    SELECT a.id, a.org_id, a.identity_id, a.current_resolver_identity_id AS resolver
    FROM approvals a
    JOIN identities r ON r.id = a.identity_id
    JOIN identities v ON v.id = a.current_resolver_identity_id
    WHERE a.status = 'pending'
      AND r.org_id = a.org_id
      AND v.org_id = a.org_id
      AND a.current_resolver_identity_id <> a.identity_id
),
chain AS (
    SELECT p.id AS approval_id, i.parent_id AS ancestor, 1 AS depth
    FROM pending p JOIN identities i ON i.id = p.identity_id
    WHERE i.parent_id IS NOT NULL
    UNION ALL
    SELECT c.approval_id, i.parent_id, c.depth + 1
    FROM chain c JOIN identities i ON i.id = c.ancestor
    WHERE i.parent_id IS NOT NULL AND c.depth < 50
)
SELECT p.org_id AS "org_id!",
       'approvals' AS "subject_table!",
       p.id AS "subject_id!",
       'requester ' || p.identity_id || ', resolver ' || p.resolver AS "detail!"
FROM pending p
WHERE NOT EXISTS (
    SELECT 1 FROM chain c WHERE c.approval_id = p.id AND c.ancestor = p.resolver
)
ORDER BY p.org_id, p.id
