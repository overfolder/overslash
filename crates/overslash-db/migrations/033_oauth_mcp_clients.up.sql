-- Dynamically-registered OAuth clients for the MCP Authorization Server.
-- Public clients only (PKCE, no client_secret). Registered via RFC 7591
-- (POST /oauth/register) and revocable from the Org Settings dashboard.

CREATE TABLE oauth_mcp_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           TEXT NOT NULL UNIQUE,
    client_name         TEXT,
    redirect_uris       TEXT[] NOT NULL,
    software_id         TEXT,
    software_version    TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ,
    created_ip          TEXT,
    created_user_agent  TEXT,
    is_revoked          BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_oauth_mcp_clients_active
    ON oauth_mcp_clients (created_at DESC)
    WHERE is_revoked = false;
