-- No-op: the up migration cleared stale `secret_name` values on OAuth-service
-- instances. Rollback cannot recover the originals and there is no meaningful
-- downgrade.
SELECT 1;
