DROP TABLE IF EXISTS pending_mcp_elicitations;

ALTER TABLE mcp_client_agent_bindings
    DROP COLUMN IF EXISTS elicitation_enabled;

ALTER TABLE oauth_mcp_clients
    DROP COLUMN IF EXISTS capabilities,
    DROP COLUMN IF EXISTS client_info,
    DROP COLUMN IF EXISTS protocol_version,
    DROP COLUMN IF EXISTS last_session_id;
