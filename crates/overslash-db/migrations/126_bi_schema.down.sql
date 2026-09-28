-- The `bi_reader` role is cluster-wide and may serve other databases on the
-- instance, so it is left in place; dropping the schema revokes its grants.
DROP SCHEMA bi CASCADE;
