-- Opaque partner metadata on BYOC credentials (token-vault addendum, §6.2 of
-- docs/design/agent-credential-provisioning.md).
--
-- A white-label partner (e.g. Overfolder) cannot tell whether a registered
-- credential matches its own vault copy from ids + provider keys alone. This
-- column lets the creating/updating caller stamp provenance — e.g.
-- {"source":"overfolder","vault_secret_id":"<uuid>","vault_updated_at":"<ts>"} —
-- echoed verbatim on create/list/get so reconciliation is a stateless
-- read-and-compare against the partner's own row.
--
-- The value is a *claim*, not content, and is opaque to Overslash (no
-- semantics, no indexing promises beyond echo). Any path that replaces the
-- encrypted client pair must clear or rewrite it so a stale claim never masks a
-- foreign credential.

ALTER TABLE byoc_credentials ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN byoc_credentials.metadata IS
    'Opaque caller-supplied key/value claim (provenance tag). Echoed verbatim; cleared/rewritten whenever the encrypted client pair is replaced.';
