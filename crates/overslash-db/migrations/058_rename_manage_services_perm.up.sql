-- Permission split: `manage_services` → `manage_services_own` + `manage_services_share`
-- (per docs/design/agent-self-management.md §1). The new platform actions
-- (create_service, update_service, list_services, get_service) anchor on
-- `manage_services_own`; the social half (granting to non-Myself groups)
-- continues to require admin and lives under `manage_services_share`.
--
-- Existing deployments have user-written permission rules with the old
-- `overslash:manage_services:*` anchor. Without this migration, those rules
-- would no-op against the renamed action and agents would silently lose the
-- ability to create/update services they previously had permission for.
--
-- Rewrite the *own* half (the safe one). Customers who actually want the
-- share half re-grant it explicitly through the dashboard — preserving the
-- design intent that `_share` is a deliberate, social act.

-- `'overslash:manage_services:'` is 26 chars (1..26 inclusive of the colon),
-- so the suffix starts at position 27.
UPDATE permission_rules
SET action_pattern = 'overslash:manage_services_own:' || substring(action_pattern from 27)
WHERE action_pattern LIKE 'overslash:manage_services:%';
