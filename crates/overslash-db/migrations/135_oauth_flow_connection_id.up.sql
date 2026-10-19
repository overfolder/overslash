-- The connection a completed flow produced, stamped with `completed_at`.
-- A URL-mode MCP elicitation that waited on the flow reports it back to the
-- agent — which connection, which account, which services now use it —
-- instead of the original response and its now-spent link.
ALTER TABLE oauth_connection_flows ADD COLUMN connection_id UUID;

COMMENT ON COLUMN oauth_connection_flows.connection_id IS
    'The connection the OAuth callback created or upgraded. Set with completed_at.';
