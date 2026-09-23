DROP INDEX IF EXISTS idx_pending_mcp_elicit_agent_cancelled;

ALTER TABLE mcp_client_agent_bindings
    ADD COLUMN elicitation_enabled BOOLEAN NOT NULL DEFAULT false;

-- Inverse of the up migration's carry-over. A binding that never opted out is
-- restored as enabled, which under the pre-123 semantics means "on" — correct
-- for anyone who adopted the new default, and the closest available answer for
-- anyone who simply never touched it.
UPDATE mcp_client_agent_bindings
   SET elicitation_enabled = NOT elicitation_opted_out;

ALTER TABLE mcp_client_agent_bindings
    DROP COLUMN elicitation_opted_out;
