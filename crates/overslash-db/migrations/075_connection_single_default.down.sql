-- Drop the single-default invariant. The demotions performed by the up
-- migration are not reversible (the original multi-default state carried no
-- information worth restoring), so this only removes the index.

DROP INDEX IF EXISTS idx_connections_one_default;
