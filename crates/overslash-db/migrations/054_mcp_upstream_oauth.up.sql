-- Nested OAuth: Overslash acting as MCP client to upstream MCP servers.
--
-- Three tables:
--   * mcp_upstream_connections — one row per (identity, upstream resource).
--     Tracks status (pending_auth / ready / revoked / error) and the DCR'd
--     client_id at the upstream AS.
--   * mcp_upstream_tokens — versioned, encrypted-at-rest tokens. Multiple
--     rows per connection allowed for rotation; the current row has
--     superseded_at IS NULL.
--   * mcp_upstream_flows — in-progress OAuth flows. Opaque base62 id is the
--     "state" parameter sent to the upstream AS; the row is the trusted
--     source of identity, resource, and PKCE verifier. Single-use via
--     consumed_at; 10-minute TTL via exp.

-- ---------------------------------------------------------------------------
-- mcp_upstream_connections
-- ---------------------------------------------------------------------------
CREATE TABLE mcp_upstream_connections (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id         UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    org_id              UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    upstream_resource   TEXT        NOT NULL,
    upstream_client_id  TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'pending_auth'
                                    CHECK (status IN ('pending_auth', 'ready', 'revoked', 'error')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_refreshed_at   TIMESTAMPTZ,

    -- One connection per (identity, upstream). Re-auth rotates tokens
    -- on the same row rather than creating duplicates.
    CONSTRAINT mcp_upstream_connections_unique UNIQUE (identity_id, upstream_resource)
);

CREATE INDEX idx_mcp_upstream_connections_org
    ON mcp_upstream_connections (org_id);

-- ---------------------------------------------------------------------------
-- mcp_upstream_tokens
-- ---------------------------------------------------------------------------
-- Encrypted at rest. Ciphertext is `nonce || aes_gcm_ciphertext` per
-- crates/overslash-core/src/crypto.rs. Key comes from the configured
-- secret-vault key.
--
-- Versioned: rotation inserts a new row and stamps the previous one's
-- superseded_at. The current token for a connection is the unique row
-- with superseded_at IS NULL.
CREATE TABLE mcp_upstream_tokens (
    id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id               UUID        NOT NULL REFERENCES mcp_upstream_connections(id) ON DELETE CASCADE,
    access_token_ciphertext     BYTEA       NOT NULL,
    refresh_token_ciphertext    BYTEA,
    access_token_expires_at     TIMESTAMPTZ,
    scope                       TEXT,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at               TIMESTAMPTZ
);

-- At most one current (non-superseded) token per connection.
CREATE UNIQUE INDEX idx_mcp_upstream_tokens_current
    ON mcp_upstream_tokens (connection_id)
    WHERE superseded_at IS NULL;

-- ---------------------------------------------------------------------------
-- mcp_upstream_flows
-- ---------------------------------------------------------------------------
-- Opaque flow-id (base62, ~22 chars from 16 random bytes) is both the URL
-- short-id and the OAuth `state` parameter. Trusted fields live here, never
-- in the URL.
CREATE TABLE mcp_upstream_flows (
    id                      TEXT        PRIMARY KEY,
    identity_id             UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    org_id                  UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    upstream_resource       TEXT        NOT NULL,
    upstream_client_id      TEXT        NOT NULL,
    -- The AS issuer URL discovered at mint time. Persisted (rather than
    -- re-derived from upstream_authorize_url) so that path-based
    -- multi-tenant ASes — e.g. issuer `https://login.example.com/tenant/abc`
    -- with authorize endpoint at `…/tenant/abc/oauth/authorize` — keep
    -- working at callback time.
    upstream_as_issuer      TEXT        NOT NULL,
    upstream_token_endpoint TEXT        NOT NULL,
    upstream_authorize_url  TEXT        NOT NULL,
    pkce_code_verifier      TEXT        NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    consumed_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_ip              TEXT,
    created_user_agent      TEXT
);

-- Lookup by identity for the dashboard "Connections" page (most-recent first).
CREATE INDEX idx_mcp_upstream_flows_identity
    ON mcp_upstream_flows (identity_id, created_at DESC);

-- Cleanup sweep: expired & unconsumed flows.
CREATE INDEX idx_mcp_upstream_flows_expires_at
    ON mcp_upstream_flows (expires_at)
    WHERE consumed_at IS NULL;
