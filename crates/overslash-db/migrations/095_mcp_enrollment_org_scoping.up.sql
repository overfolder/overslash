-- MCP enrollment org-scoping (docs/design/mcp-enrollment-org-scoping.md).
--
-- Two changes make a corp subdomain the enrollment boundary:
--
-- 1. Org-stamp the DCR client. `org_id` is stamped from the request's
--    subdomain context at `POST /oauth/register`: a subdomain registration
--    locks the client to that org; a root (or pre-migration) registration
--    leaves it NULL = usable across whichever org the user's session is on.
--    Nullable for back-compat — existing clients keep NULL ("any subdomain").
--
-- 2. Make the binding uniqueness org-aware. The old
--    `UNIQUE (user_identity_id, client_id)` is migrated to
--    `(user_identity_id, client_id, org_id)` so the same user+client can bind
--    a distinct agent per org (the root multi-org case: one NULL-scoped client
--    enrolled into two orgs the user belongs to). Existing rows already carry
--    `org_id NOT NULL`, so the constraint swap is safe.

ALTER TABLE oauth_mcp_clients
    ADD COLUMN org_id UUID REFERENCES orgs(id) ON DELETE CASCADE;

COMMENT ON COLUMN oauth_mcp_clients.org_id IS
    'Org this DCR client is locked to (stamped from the subdomain at registration). NULL = root/multi-org: usable on any subdomain, absent from any org''s admin MCP-Clients list.';

CREATE INDEX idx_oauth_mcp_clients_org
    ON oauth_mcp_clients (org_id);

ALTER TABLE mcp_client_agent_bindings
    DROP CONSTRAINT mcp_client_agent_bindings_user_identity_id_client_id_key,
    ADD CONSTRAINT mcp_client_agent_bindings_user_client_org_key
        UNIQUE (user_identity_id, client_id, org_id);
