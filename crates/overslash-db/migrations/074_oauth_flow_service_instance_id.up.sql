-- When `POST /v1/services` initiates an OAuth flow as part of setting up a
-- new service, the flow row carries the freshly-created instance id so the
-- callback knows which row to bind the new connection to. NULL is the
-- low-level path where the caller is not orchestrating a service alongside.
--
-- `ON DELETE SET NULL` so a stale flow whose instance was deleted before the
-- callback fires just falls through to the standard connection-only path,
-- rather than failing the OAuth dance with a constraint violation.

ALTER TABLE oauth_connection_flows
    ADD COLUMN service_instance_id UUID REFERENCES service_instances(id) ON DELETE SET NULL;
