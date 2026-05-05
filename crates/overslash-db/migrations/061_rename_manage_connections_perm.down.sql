-- Reverse the permission rename. Lossy if a customer has created a fresh
-- `manage_connections_own` rule post-061 (the down migration cannot tell
-- it apart from a migrated one), but acceptable for rollback in dev.

-- `'overslash:manage_connections_own:'` is 33 chars, suffix at position 34.
UPDATE permission_rules
SET action_pattern = 'overslash:manage_connections:' || substring(action_pattern from 34)
WHERE action_pattern LIKE 'overslash:manage_connections_own:%';
