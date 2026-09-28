-- URL-mode MCP elicitation.
--
-- Overslash hands a user a browser link (provider OAuth, credential entry,
-- an approval) through the MCP client, then waits for that browser flow to
-- finish before answering the tool call. Two things were missing to do that.
--
-- 1. An OAuth connect flow recorded that its gate link was *opened*
--    (`consumed_at`) but not how it *ended*. The callback now stamps
--    `completed_at` on success and `failed_at` on failure, which is what a
--    waiting tool call polls.
ALTER TABLE oauth_connection_flows
    ADD COLUMN completed_at TIMESTAMPTZ,
    ADD COLUMN failed_at TIMESTAMPTZ;

COMMENT ON COLUMN oauth_connection_flows.completed_at IS
    'Set by the OAuth callback when the flow produced a connection. Polled by URL-mode MCP elicitation.';
COMMENT ON COLUMN oauth_connection_flows.failed_at IS
    'Set by the OAuth callback when the flow ended in an error. Polled by URL-mode MCP elicitation.';

-- 2. On a 2025-era MCP connection the client answers a URL elicitation
--    (accept / decline / cancel) with a separate POST that may land on a
--    different replica from the one holding the tool call's SSE stream. This
--    table carries that answer across. A 2026-07-28 connection never uses it:
--    there the answer rides on the retried request itself.
CREATE TABLE mcp_url_elicitations (
    elicit_id TEXT PRIMARY KEY,
    agent_identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    action TEXT CHECK (action IN ('accept', 'decline', 'cancel')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    answered_at TIMESTAMPTZ
);

-- The purge sweep deletes by age.
CREATE INDEX idx_mcp_url_elicitations_created ON mcp_url_elicitations (created_at);
