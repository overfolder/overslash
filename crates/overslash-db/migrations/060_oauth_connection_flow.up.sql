-- Gated authorize flow for HTTP-OAuth providers.
--
-- Mitigates the Obsidian "MCP meets OAuth" pitfall (2025): when an agent
-- delivers an authorize URL to the user over chat, the user sees the raw
-- provider domain and has no Overslash-branded checkpoint to confirm
-- *which agent* triggered the flow on *which Overslash account*. We need
-- the same fail-fast gate that `mcp_upstream_flows` already provides for
-- the upstream-MCP path, but for first-party HTTP OAuth (GitHub, Google,
-- Eventbrite, …).
--
-- The opaque base62 `id` is the URL short-id used in
-- `https://app.overslash.com/connect-authorize?id=…`. The row is the
-- trusted source of identity, expiry, PKCE verifier, and the raw provider
-- authorize URL — the URL itself never crosses MCP and is only revealed
-- by the gate handler after the session matches. White-label REST callers
-- can opt into receiving the raw URL alongside the proxied one via
-- `include_raw` on POST /v1/connections.
--
-- Single-use is enforced via `consumed_at` on the gate path — the
-- `/v1/oauth/callback` security boundary is unchanged and still keys off
-- the `state` parameter validated server-side.

CREATE TABLE oauth_connection_flows (
    id                      TEXT        PRIMARY KEY,
    org_id                  UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- The identity the resulting connection will bind to. For agents this
    -- is the owner-user (via on_behalf_of resolution at mint time).
    identity_id             UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    -- The agent that initiated the flow, preserved for audit. Equals
    -- `identity_id` when the caller was already the owner-user.
    actor_identity_id       UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    provider_key            TEXT        NOT NULL,
    -- Pinned BYOC credential row (NULL = cascade resolver picks at mint
    -- time and we re-derive on callback the same way).
    byoc_credential_id      UUID,
    scopes                  TEXT[]      NOT NULL DEFAULT '{}',
    pkce_code_verifier      TEXT,
    upstream_authorize_url  TEXT        NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    consumed_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_ip              TEXT,
    created_user_agent      TEXT
);

-- Lookup by identity for any future "active connect flows" UI.
CREATE INDEX idx_oauth_connection_flows_identity
    ON oauth_connection_flows (identity_id, created_at DESC);

-- Cleanup sweep: expired & unconsumed flows.
CREATE INDEX idx_oauth_connection_flows_expires_at
    ON oauth_connection_flows (expires_at)
    WHERE consumed_at IS NULL;
