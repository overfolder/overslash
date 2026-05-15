-- Billing tables for Cloud tier support (Team org subscriptions via Stripe).
-- Applies only when CLOUD_BILLING=true; schema is always migrated so
-- self-hosted deployments can upgrade without conditional migration logic.

-- stripe_customer_id: one Stripe Customer per human user.
ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;
CREATE UNIQUE INDEX users_stripe_customer
    ON users (stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;

-- Active subscription per Team org (personal orgs never have a row here).
CREATE TABLE org_subscriptions (
    org_id                 UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    stripe_subscription_id TEXT NOT NULL UNIQUE,
    stripe_customer_id     TEXT NOT NULL,
    plan                   TEXT NOT NULL DEFAULT 'team',
    seats                  INTEGER NOT NULL DEFAULT 2,
    status                 TEXT NOT NULL,
    currency               TEXT NOT NULL,
    current_period_start   TIMESTAMPTZ,
    current_period_end     TIMESTAMPTZ,
    cancel_at_period_end   BOOLEAN NOT NULL DEFAULT false,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Holds the desired org parameters from the moment a user initiates Stripe
-- Checkout until the webhook confirms payment and the org is provisioned.
-- Keyed on the Stripe session_id (cs_xxx) so the webhook can look it up.
CREATE TABLE pending_checkouts (
    id               TEXT PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_name         TEXT NOT NULL,
    org_slug         TEXT NOT NULL,
    seats            INTEGER NOT NULL,
    currency         TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '2 hours',
    fulfilled_org_id UUID
);

CREATE INDEX idx_pending_checkouts_user ON pending_checkouts (user_id);
