-- Per-instance opt-out of the default-connection fallback.
--
-- At execution time a service instance with no explicit `connection_id` falls
-- through to `find_my_connection_by_provider` — the identity's *default*
-- connection for the provider. White-label partners who mint a dedicated
-- connection per service want to forbid that silent fallback so a service never
-- borrows whatever default the user happens to have.
--
-- Defaults to `true` to preserve today's behavior for every existing row.
ALTER TABLE service_instances
    ADD COLUMN use_default_connection BOOLEAN NOT NULL DEFAULT true;
