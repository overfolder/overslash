-- Invariant byoc_provider_mismatch (D122).
-- A connection whose BYOC client is for a different OAuth provider.
-- byoc_binding::usable_byoc_pin refuses it at refresh time.
SELECT c.org_id AS "org_id!",
       'connections' AS "subject_table!",
       c.id AS "subject_id!",
       'byoc_credential ' || b.id || ' is ' || b.provider_key
           || ', connection is ' || c.provider_key AS "detail!"
FROM connections c
JOIN byoc_credentials b ON b.id = c.byoc_credential_id
WHERE b.org_id = c.org_id
  AND b.provider_key <> c.provider_key
ORDER BY c.org_id, c.id
