-- Protect a connection from the service-deletion auto-cleanup.
--
-- Deleting a service instance now also deletes the OAuth connection it was
-- bound to, but only when the connection is orphaned (no other service_instance
-- references it) AND not explicitly preserved. `keep` is the per-connection
-- preserve flag: when true, the connection survives service deletion regardless
-- of reference count. Default false keeps existing connections eligible for
-- cleanup exactly as if the flag had always been off.

ALTER TABLE connections ADD COLUMN keep boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN connections.keep IS
    'When true, this connection is never auto-deleted by service deletion, even when no service references it.';
