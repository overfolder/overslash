-- MCP OAuth Authorization Server schema — consolidated.
--
-- Three tables back the flow documented in docs/design/mcp-oauth-transport.md:
--
--   1. oauth_mcp_clients           — RFC 7591 Dynamic Client Registration.
--   2. mcp_refresh_tokens          — rotating refresh tokens (OAuth 2.1 BCP).
--   3. mcp_client_agent_bindings   — per (user, client) → agent identity.
--      Populated by the `/oauth/consent` step. The binding is what makes
--      repeat logins skip the consent screen: on a second authorize call
--      we reuse the previously-enrolled agent.

-- --------------------------------------------------------------------------
-- oauth_mcp_clients
-- --------------------------------------------------------------------------
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

-- --------------------------------------------------------------------------
-- mcp_refresh_tokens
-- --------------------------------------------------------------------------
-- Refresh tokens minted by the MCP Authorization Server.
-- Stored hashed (sha256) and single-use-rotating per OAuth 2.1 BCP:
-- every successful refresh revokes the presented token and links the
-- freshly issued one via replaced_by_id. Reuse of a revoked token is
-- treated as a replay — the whole chain is revoked at resolution time.
--
-- `identity_id` references the AGENT identity enrolled at consent time
-- (not the human user). Tokens bound to user-kind identities are no longer
-- issued.

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

-- --------------------------------------------------------------------------
-- mcp_client_agent_bindings
-- --------------------------------------------------------------------------
-- Per-(user, MCP client) binding to an agent identity enrolled during the
-- /oauth/consent step. The uniqueness constraint on
-- (user_identity_id, client_id) makes the consent-finish handler's upsert
-- idempotent across retries.

CREATE TABLE mcp_client_agent_bindings (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_identity_id    UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    client_id           TEXT        NOT NULL REFERENCES oauth_mcp_clients(client_id) ON DELETE CASCADE,
    agent_identity_id   UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_identity_id, client_id)
);

CREATE INDEX idx_mcp_client_agent_bindings_user
    ON mcp_client_agent_bindings (user_identity_id);

CREATE INDEX idx_mcp_client_agent_bindings_agent
    ON mcp_client_agent_bindings (agent_identity_id);
