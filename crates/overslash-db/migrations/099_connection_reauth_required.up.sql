-- Persisted re-authorization flag on connections (token-vault addendum, §6.1 of
-- docs/design/agent-credential-provisioning.md).
--
-- When a BYOC credential's client_id/secret is replaced in place (PUT
-- /v1/byoc-credentials/{id}), any connection pinned to that credential holds
-- access/refresh tokens minted under the OLD OAuth app — they will stop
-- refreshing. Rather than let a refresh fail at some random later call, the
-- replace path proactively sets this flag on the pinned connections. The action
-- auth path short-circuits a flagged connection to the existing
-- `reauth_required` recovery envelope (with a freshly minted reconnect URL); a
-- fresh valid token write (the reauth callback) clears the flag.

ALTER TABLE connections ADD COLUMN reauth_required boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN connections.reauth_required IS
    'When true, the connection must be re-authorized before use (e.g. its pinned BYOC client was replaced). Cleared when fresh tokens are written.';
