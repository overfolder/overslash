-- Org default: seed a newly-created first-level agent with the four
-- `overslash:*_own` self-setup permission rules.
--
-- Mirrors `default_deferred_execution` (migration 062) in shape: an org policy
-- consumed at identity-creation time, never retroactive. Flipping it does not
-- touch agents that already exist, and the rules it seeds are ordinary
-- `permission_rules` rows an admin can revoke individually.
ALTER TABLE orgs
    ADD COLUMN default_agent_self_setup boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN orgs.default_agent_self_setup IS
    'When true (default), a newly-created first-level agent (depth = 1) is seeded with the four overslash:*_own self-setup permission rules: manage_services_own, manage_templates_own, manage_connections_own, request_secrets_own. Existing agents are not touched when this flips.';
