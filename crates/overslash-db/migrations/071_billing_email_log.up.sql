-- TODO.md §1.1: idempotency + audit log for billing transactional emails
-- (receipt / dunning / cancellation). One row per (Stripe event, email kind).
-- The composite UNIQUE protects against double-send on Stripe webhook
-- retries: the handler inserts the row first, then renders + sends, then
-- stamps `sent_at`. Rows with `sent_at IS NULL` represent claimed-but-not-
-- yet-delivered attempts (transient mailer failure) and are the primary
-- signal for manual replay during incidents. Billing email is exempt from
-- the `welcome_emails_unsubscribed_at` user preference by policy, so this
-- table does NOT join through `email_unsubscribe_tokens`.

CREATE TABLE billing_email_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id TEXT NOT NULL,
    kind            TEXT NOT NULL,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ,
    CONSTRAINT billing_email_log_kind_check
        CHECK (kind IN ('invoice_paid', 'invoice_payment_failed', 'subscription_canceled')),
    CONSTRAINT billing_email_log_event_kind_unique
        UNIQUE (stripe_event_id, kind)
);

CREATE INDEX billing_email_log_user_id
    ON billing_email_log (user_id);
CREATE INDEX billing_email_log_attempted_at
    ON billing_email_log (attempted_at);
