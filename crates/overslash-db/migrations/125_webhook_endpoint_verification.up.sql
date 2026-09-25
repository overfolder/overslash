-- Webhook endpoint-ownership verification (CASA 7.1.2).
--
-- A new subscription starts `pending_verification`. Registration POSTs a
-- signed `webhook.verification` event carrying a random challenge to the URL;
-- the endpoint proves it is controlled by the registrant by echoing the
-- challenge back with a 2xx. Only then does the subscription become
-- `verified` and receive events. Events raised while it is pending are
-- recorded as held deliveries (`webhook_deliveries.held_reason`) and released
-- to the retry sweep the moment it verifies.
--
-- Grandfathering, the compensating control for subscriptions that predate
-- the handshake: every existing row is marked `verified` as of this migration
-- with `grandfathered = true`, so current consumers keep receiving events
-- without a flag day. The flag stays until the owner re-runs verification
-- (`POST /v1/webhooks/{id}/verify`), which clears it on success. Every
-- subscription created from here on starts pending — the column default
-- flips after the backfill.
ALTER TABLE webhook_subscriptions
    ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'verified'
        CHECK (verification_status IN ('pending_verification', 'verified')),
    ADD COLUMN verified_at TIMESTAMPTZ,
    ADD COLUMN grandfathered BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN verification_attempted_at TIMESTAMPTZ,
    ADD COLUMN verification_error TEXT;

COMMENT ON COLUMN webhook_subscriptions.verification_status IS
    'pending_verification until the endpoint echoes the ownership challenge; only verified subscriptions receive events.';
COMMENT ON COLUMN webhook_subscriptions.grandfathered IS
    'Marked verified by migration 125 without a handshake (predates CASA 7.1.2). Cleared by a successful re-verification.';
COMMENT ON COLUMN webhook_subscriptions.verification_error IS
    'Why the last handshake failed. NULL after a success.';

UPDATE webhook_subscriptions
   SET verified_at = now(),
       grandfathered = true;

ALTER TABLE webhook_subscriptions
    ALTER COLUMN verification_status SET DEFAULT 'pending_verification';

ALTER TABLE webhook_deliveries ADD COLUMN held_reason TEXT;

COMMENT ON COLUMN webhook_deliveries.held_reason IS
    'Set while the delivery is held back and not dialed (pending_verification). NULL once released or for a normal delivery.';
