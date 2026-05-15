DROP TABLE IF EXISTS pending_checkouts;
DROP TABLE IF EXISTS org_subscriptions;
DROP INDEX IF EXISTS users_stripe_customer;
ALTER TABLE users DROP COLUMN IF EXISTS stripe_customer_id;
