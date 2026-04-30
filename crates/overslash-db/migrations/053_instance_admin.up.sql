-- Instance admin flag — a per-user privilege set out-of-band by an operator
-- via psql. The only elevated capability today is creating new orgs with
-- plan='free_unlimited' (bypassing Stripe checkout) through
-- POST /v1/orgs/free-unlimited.
--
-- Restricted to users with a root-domain Overslash login. Federated
-- org-only users (overslash_idp_provider IS NULL) cannot be marked
-- instance admin — enforced at DB level so a stray UPDATE can't break
-- the invariant.

ALTER TABLE users
    ADD COLUMN is_instance_admin BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE users
    ADD CONSTRAINT users_instance_admin_requires_overslash_idp
    CHECK (NOT is_instance_admin OR overslash_idp_provider IS NOT NULL);

-- Partial index: rows are vanishingly rare, so we only index the
-- truthy ones. Currently unused at runtime (the extractor looks up
-- by user_id, not by flag), but cheap and useful for ops queries.
CREATE INDEX idx_users_is_instance_admin
    ON users (is_instance_admin) WHERE is_instance_admin;
