-- Refresh tokens minted by the MCP Authorization Server.
-- Stored hashed (sha256) and single-use-rotating per OAuth 2.1 BCP:
-- every successful refresh revokes the presented token and links the
-- freshly issued one via replaced_by_id. Reuse of a revoked token is
-- treated as a replay — the whole chain is revoked at resolution time.

CREATE TABLE mcp_refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       TEXT NOT NULL REFERENCES oauth_mcp_clients(client_id) ON DELETE CASCADE,
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    hash            BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by_id  UUID REFERENCES mcp_refresh_tokens(id)
);

CREATE UNIQUE INDEX idx_mcp_refresh_tokens_hash
    ON mcp_refresh_tokens (hash);

CREATE INDEX idx_mcp_refresh_tokens_active_identity
    ON mcp_refresh_tokens (identity_id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_mcp_refresh_tokens_client
    ON mcp_refresh_tokens (client_id);
