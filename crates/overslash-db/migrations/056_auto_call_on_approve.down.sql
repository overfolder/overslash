DROP INDEX IF EXISTS idx_executions_unread;

ALTER TABLE executions
    DROP COLUMN IF EXISTS result_viewed_at;

ALTER TABLE mcp_client_agent_bindings
    DROP COLUMN IF EXISTS auto_call_on_approve;
