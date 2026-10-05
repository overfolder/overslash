-- Invariant owner_cross_org.
-- A row owned by, or chained to, an identity of another org. The identity
-- foreign keys are single-column, so the database itself does not stop it;
-- every scope filters on org_id, so such a row is invisible to its owner
-- and reachable from the wrong tenant. `subject_table` names the reference.
SELECT x.org_id AS "org_id!",
       x.subject_table AS "subject_table!",
       x.subject_id AS "subject_id!",
       x.detail AS "detail!"
FROM (
    SELECT si.org_id, 'service_instances' AS subject_table, si.id AS subject_id,
           'owner_identity_id ' || i.id || ' in org ' || i.org_id AS detail
    FROM service_instances si JOIN identities i ON i.id = si.owner_identity_id
    WHERE i.org_id <> si.org_id
    UNION ALL
    SELECT c.org_id, 'connections', c.id,
           'identity_id ' || i.id || ' in org ' || i.org_id
    FROM connections c JOIN identities i ON i.id = c.identity_id
    WHERE i.org_id <> c.org_id
    UNION ALL
    SELECT b.org_id, 'byoc_credentials', b.id,
           'identity_id ' || i.id || ' in org ' || i.org_id
    FROM byoc_credentials b JOIN identities i ON i.id = b.identity_id
    WHERE i.org_id <> b.org_id
    UNION ALL
    SELECT s.org_id, 'secrets', s.id,
           'owner_identity_id ' || i.id || ' in org ' || i.org_id
    FROM secrets s JOIN identities i ON i.id = s.owner_identity_id
    WHERE i.org_id <> s.org_id
    UNION ALL
    SELECT t.org_id, 'service_templates', t.id,
           'owner_identity_id ' || i.id || ' in org ' || i.org_id
    FROM service_templates t JOIN identities i ON i.id = t.owner_identity_id
    WHERE i.org_id <> t.org_id
    UNION ALL
    SELECT r.org_id, 'permission_rules', r.id,
           'identity_id ' || i.id || ' in org ' || i.org_id
    FROM permission_rules r JOIN identities i ON i.id = r.identity_id
    WHERE i.org_id <> r.org_id
    UNION ALL
    -- The chain approvals bubble along and permissions inherit through.
    SELECT c.org_id, 'identities', c.id,
           'parent_id/owner_id ' || p.id || ' in org ' || p.org_id
    FROM identities c JOIN identities p ON p.id = c.parent_id OR p.id = c.owner_id
    WHERE p.org_id <> c.org_id
) x
ORDER BY x.org_id, x.subject_table, x.subject_id
