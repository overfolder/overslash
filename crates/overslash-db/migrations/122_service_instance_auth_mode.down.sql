-- Dropping the column returns every instance to "the template's default mode".
-- An instance that had picked the non-default alternative therefore changes
-- which credential it authenticates with; its bound secret and its connection
-- both survive the drop, so re-applying the migration restores it only if the
-- mode is set again.
ALTER TABLE service_instances DROP COLUMN auth_mode;
