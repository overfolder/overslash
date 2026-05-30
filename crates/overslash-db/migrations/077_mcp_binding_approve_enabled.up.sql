-- Per-(user, MCP client) → agent binding gains a downstream-approval toggle.
-- When true, the `overslash_approve` MCP tool is visible in tools/list for
-- this connection (the agent may resolve approvals requested by its
-- descendants). The default is *class-based*: human-on-the-screen clients
-- (claude.ai, ChatGPT, Codex, Claude Code, ...) get it on; autonomous agents
-- (openclaw and any unknown client) get it off. The concrete value is
-- materialized at enrollment (see routes/oauth.rs) and overridable from the
-- dashboard — the column never holds NULL. See the agent detail page's
-- "Connection Options".

ALTER TABLE mcp_client_agent_bindings
    ADD COLUMN approve_enabled BOOLEAN NOT NULL DEFAULT true;

-- Backfill existing rows: only the column default of `true` lands first, so
-- flip autonomous/unknown clients to false. Keep this allowlist in sync with
-- `OauthMcpClientRow::is_human_on_screen` in
-- crates/overslash-db/src/repos/oauth_mcp_client.rs.
UPDATE mcp_client_agent_bindings b
   SET approve_enabled = false
  FROM oauth_mcp_clients c
 WHERE c.client_id = b.client_id
   AND NOT (
        lower(coalesce(c.client_name, ''))            ~ '(claude|chatgpt|codex|openai)'
     OR lower(coalesce(c.software_id, ''))            ~ '(claude|chatgpt|codex|openai)'
     OR lower(coalesce(c.client_info->>'name', ''))   ~ '(claude|chatgpt|codex|openai)'
   );
