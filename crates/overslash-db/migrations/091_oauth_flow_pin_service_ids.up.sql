-- Multi-instance atomic pinning for the OAuth-orchestrated connect flow.
--
-- `service_instance_id` (migration 074) let a `POST /v1/services` flow bind the
-- resulting connection back onto a single just-created instance. White-label
-- callers now need to pin the new connection to *several* instances at once, so
-- carry the full list on the flow row. The singular column stays for in-flight
-- flows created before this migration; the callback reads both and merges them.
ALTER TABLE oauth_connection_flows
    ADD COLUMN pin_service_instance_ids UUID[] NOT NULL DEFAULT '{}';
