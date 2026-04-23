DROP INDEX IF EXISTS idx_mcp_client_agent_bindings_agent;
DROP INDEX IF EXISTS idx_mcp_client_agent_bindings_user;
DROP TABLE IF EXISTS mcp_client_agent_bindings;

DROP INDEX IF EXISTS idx_mcp_refresh_tokens_client;
DROP INDEX IF EXISTS idx_mcp_refresh_tokens_active_identity;
DROP INDEX IF EXISTS idx_mcp_refresh_tokens_hash;
DROP TABLE IF EXISTS mcp_refresh_tokens;

DROP INDEX IF EXISTS idx_oauth_mcp_clients_active;
DROP TABLE IF EXISTS oauth_mcp_clients;
