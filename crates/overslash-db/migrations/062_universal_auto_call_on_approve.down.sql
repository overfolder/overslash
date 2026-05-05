ALTER TABLE mcp_client_agent_bindings
    ADD COLUMN auto_call_on_approve boolean NOT NULL DEFAULT true;

UPDATE mcp_client_agent_bindings b
   SET auto_call_on_approve = false
  FROM identities i
 WHERE b.agent_identity_id = i.id
   AND i.auto_call_on_approve = false;

ALTER TABLE identities
    DROP COLUMN auto_call_on_approve;

ALTER TABLE orgs
    DROP COLUMN default_deferred_execution;
