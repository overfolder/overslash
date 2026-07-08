-- Reverse 095_mcp_enrollment_org_scoping.
--
-- Note: rows whose (user_identity_id, client_id) pair collides across orgs
-- would block restoring the narrower unique constraint. That can only happen
-- if a user enrolled the same client into multiple orgs after this migration;
-- resolve such rows manually before rolling back.

ALTER TABLE mcp_client_agent_bindings
    DROP CONSTRAINT mcp_client_agent_bindings_user_client_org_key,
    ADD CONSTRAINT mcp_client_agent_bindings_user_identity_id_client_id_key
        UNIQUE (user_identity_id, client_id);

DROP INDEX idx_oauth_mcp_clients_org;

ALTER TABLE oauth_mcp_clients
    DROP COLUMN org_id;
