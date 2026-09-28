-- A composite foreign key tying an API key's org to its bound identity.
--
-- `api_keys` carried two independent foreign keys — `org_id -> orgs(id)` and
-- `identity_id -> identities(id)` — and nothing that related the pair. A
-- handler that took `org_id` from a request body and `identity_id` from the
-- same body could therefore write a key whose org and whose bound identity
-- belonged to different tenants, and the database would accept it. One did:
-- see the V2 finding in docs/compliance/casa/gap-assessment.md.
--
-- `POST /v1/api-keys` now rejects that at the boundary. This constraint is
-- what makes it impossible regardless of what any future handler does.

-- 1. The referenced pair has to be unique before it can be referenced.
--    `identities.id` is the primary key, so `(org_id, id)` is unique by
--    construction — this only gives Postgres the index it demands.
ALTER TABLE identities
    ADD CONSTRAINT identities_org_id_id_key UNIQUE (org_id, id);

-- 2. Report pre-existing mismatched rows rather than healing them. A key
--    bound across tenants is an incident, and deleting the evidence is the
--    wrong default. The ADD CONSTRAINT in step 3 would fail on such a row
--    anyway; this turns that into a message that says which rows and why.
DO $$
DECLARE
    bad_count bigint;
    bad_ids   text;
BEGIN
    SELECT count(*), string_agg(k.id::text, ', ' ORDER BY k.id)
      INTO bad_count, bad_ids
      FROM api_keys k
      JOIN identities i ON i.id = k.identity_id
     WHERE i.org_id <> k.org_id;

    IF bad_count > 0 THEN
        RAISE EXCEPTION
            'api_keys holds % cross-tenant row(s) where api_keys.org_id <> identities.org_id: %. Investigate and revoke them by hand before re-running this migration — do not delete them blindly.',
            bad_count, bad_ids;
    END IF;
END $$;

-- 3. The constraint. It subsumes the single-column `api_keys_identity_id_fkey`
--    — same parent table, same ON DELETE CASCADE, strictly stronger predicate
--    — so that one goes rather than leaving two triggers doing one job.
ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_identity_id_fkey;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_org_id_identity_id_fkey
    FOREIGN KEY (org_id, identity_id) REFERENCES identities (org_id, id)
    ON DELETE CASCADE;

-- 4. Give that cascade an index to walk — the single-column FK never had one,
--    so purging an identity already seq-scanned `api_keys`. A btree on
--    `(org_id, identity_id)` answers everything `idx_api_keys_org` answered,
--    so the narrower index is redundant once this exists.
CREATE INDEX idx_api_keys_org_identity ON api_keys (org_id, identity_id);
DROP INDEX idx_api_keys_org;
