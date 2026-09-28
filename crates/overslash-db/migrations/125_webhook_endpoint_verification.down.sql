-- Held deliveries were never sent; dropping the column would make them look
-- like normal pending rows and ship them to an unverified endpoint.
DELETE FROM webhook_deliveries WHERE held_reason IS NOT NULL;
ALTER TABLE webhook_deliveries DROP COLUMN held_reason;

ALTER TABLE webhook_subscriptions
    DROP COLUMN verification_error,
    DROP COLUMN verification_attempted_at,
    DROP COLUMN grandfathered,
    DROP COLUMN verified_at,
    DROP COLUMN verification_status;
