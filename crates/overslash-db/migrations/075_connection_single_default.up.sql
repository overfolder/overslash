-- One default connection per (identity, provider).
--
-- `connections.is_default` defaults to `true`, so historically every connection
-- was created as a default — an identity with two Google accounts ended up with
-- two `is_default = true` rows. `find_my_connection_by_provider` papered over
-- this with `ORDER BY is_default DESC, created_at DESC LIMIT 1`, but the new
-- set-default UX needs the invariant to actually hold.
--
-- First normalize existing data: keep the most-recently-connected row as the
-- default for each (identity, provider) and demote the rest. Then enforce the
-- invariant with a partial unique index so `set_default`'s "demote siblings,
-- promote target" transaction is the only way to move the flag.

UPDATE connections SET is_default = false
WHERE is_default = true
  AND id NOT IN (
      SELECT DISTINCT ON (identity_id, provider_key) id
      FROM connections
      ORDER BY identity_id, provider_key, created_at DESC
  );

CREATE UNIQUE INDEX idx_connections_one_default
    ON connections (identity_id, provider_key)
    WHERE is_default;
