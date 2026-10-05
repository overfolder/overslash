-- Invariant byoc_cross_org (D122).
-- A connection minted with a BYOC OAuth client that belongs to another org.
SELECT c.org_id AS "org_id!",
       'connections' AS "subject_table!",
       c.id AS "subject_id!",
       'byoc_credential ' || b.id || ' in org ' || b.org_id AS "detail!"
FROM connections c
JOIN byoc_credentials b ON b.id = c.byoc_credential_id
WHERE b.org_id <> c.org_id
ORDER BY c.org_id, c.id
