-- Drop the `integration_managed` flag. It conflated two unrelated axes: *who
-- refreshes* (now purely structural — a pinned `byoc_credential_id` self-refreshes
-- via that client; a null one refreshes via the orchestrated org/env cascade) and
-- *who runs the user-facing flow* (now the per-org `orgs.headless` capability,
-- migration 084). The no-client import mode it marked (`byoc_credential_id IS NULL`
-- ⇒ never refresh, inject-until-expiry) is removed: `POST /v1/connections/import`
-- now requires a `byoc_credential_id`, so every imported connection self-refreshes
-- like any pinned BYOC connection.
ALTER TABLE connections
    DROP COLUMN integration_managed;
