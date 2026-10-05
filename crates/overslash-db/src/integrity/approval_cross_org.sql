-- Invariant approval_cross_org (#737).
-- A pending approval whose requester or current resolver is an identity of
-- another org. Pending rows only: they are the live queue, and the scan
-- stays on idx_approvals_org_status as the table grows.
SELECT a.org_id AS "org_id!",
       'approvals' AS "subject_table!",
       a.id AS "subject_id!",
       'requester ' || r.id || ' in org ' || r.org_id
           || ', resolver ' || v.id || ' in org ' || v.org_id AS "detail!"
FROM approvals a
JOIN identities r ON r.id = a.identity_id
JOIN identities v ON v.id = a.current_resolver_identity_id
WHERE a.status = 'pending'
  AND (r.org_id <> a.org_id OR v.org_id <> a.org_id)
ORDER BY a.org_id, a.id
