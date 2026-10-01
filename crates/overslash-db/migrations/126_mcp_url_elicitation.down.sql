DROP TABLE IF EXISTS mcp_url_elicitations;
ALTER TABLE oauth_connection_flows
    DROP COLUMN IF EXISTS completed_at,
    DROP COLUMN IF EXISTS failed_at;
