-- Per-(user, MCP client) → agent binding gains a self-approval toggle.
-- When true, the agent on this binding may resolve approvals it itself
-- requested; the `overslash_approve_self` MCP tool also becomes visible in
-- tools/list. Default false: an agent cannot rubber-stamp its own approvals
-- unless the human at the keyboard explicitly enables it for this binding.
-- See docs/design/agent-self-management.md §2.

ALTER TABLE mcp_client_agent_bindings
    ADD COLUMN self_approve_enabled BOOLEAN NOT NULL DEFAULT false;
