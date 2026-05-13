-- Webhook DLQ digest (TODO.md §1.1, fifth bullet). Extends the email
-- infrastructure shipped in migration 068 with a second non-transactional
-- email category and a per-org per-day claim row that gates the daily send.
--
-- Per-category opt-out: welcome and digest are independent, mirroring the
-- policy that billing is exempt from non-transactional gates. Opting out of
-- the product welcome shouldn't silence webhook failure alerts, and an admin
-- who silences the digest still gets their welcome touch.
--
-- `webhook_digest_runs` is the atomic-claim row: every API replica races the
-- same `INSERT ... ON CONFLICT DO NOTHING RETURNING`, the PK guarantees
-- exactly one winner per (org_id, run_date), and the winner is responsible
-- for the org's digest that day.

BEGIN;

ALTER TABLE users
    ADD COLUMN webhook_digest_unsubscribed_at TIMESTAMPTZ;

ALTER TABLE email_unsubscribe_tokens
    DROP CONSTRAINT email_unsubscribe_tokens_purpose_check,
    ADD  CONSTRAINT email_unsubscribe_tokens_purpose_check
         CHECK (purpose IN ('welcome', 'webhook_digest'));

CREATE TABLE webhook_digest_runs (
    org_id   UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    run_date DATE NOT NULL,
    sent_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, run_date)
);

CREATE INDEX webhook_digest_runs_run_date ON webhook_digest_runs (run_date);

COMMIT;
