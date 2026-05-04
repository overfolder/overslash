-- Reverse the permission rename. Lossy if a customer has explicitly created
-- a fresh `manage_services_own` rule post-057 (the down migration cannot tell
-- it apart from a migrated one), but acceptable for rollback in dev.

-- `'overslash:manage_services_own:'` is 30 chars (1..30 inclusive of the colon),
-- so the suffix starts at position 31.
UPDATE permission_rules
SET action_pattern = 'overslash:manage_services:' || substring(action_pattern from 31)
WHERE action_pattern LIKE 'overslash:manage_services_own:%';
