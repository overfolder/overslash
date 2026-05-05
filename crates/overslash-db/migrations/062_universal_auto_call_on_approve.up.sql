-- Move `auto_call_on_approve` off `mcp_client_agent_bindings` (per-MCP-binding)
-- and onto `identities` (per-agent), so REST and white-label agents can
-- auto-execute on approve too. Add an org-level default that flips new agents
-- into "deferred execution" mode at creation time.

ALTER TABLE identities
    ADD COLUMN auto_call_on_approve boolean NOT NULL DEFAULT true;

ALTER TABLE orgs
    ADD COLUMN default_deferred_execution boolean NOT NULL DEFAULT false;

-- Preserve existing intent: any agent with at least one MCP binding that had
-- `auto_call_on_approve=false` carries that opt-out forward onto the identity.
-- The default has been TRUE since the column shipped, so the common case is a
-- no-op.
UPDATE identities i
   SET auto_call_on_approve = false
 WHERE EXISTS (
     SELECT 1 FROM mcp_client_agent_bindings b
      WHERE b.agent_identity_id = i.id
        AND b.auto_call_on_approve = false
 );

ALTER TABLE mcp_client_agent_bindings
    DROP COLUMN auto_call_on_approve;
