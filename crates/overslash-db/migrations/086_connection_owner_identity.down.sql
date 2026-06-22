-- Irreversible data migration: the original agent identity_id is not retained,
-- so re-pointing to the owner cannot be undone. No-op down; connections remain
-- bound to the owner identity.
SELECT 1;
