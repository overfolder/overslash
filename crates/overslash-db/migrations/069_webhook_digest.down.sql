BEGIN;

DROP TABLE IF EXISTS webhook_digest_runs;

ALTER TABLE email_unsubscribe_tokens
    DROP CONSTRAINT email_unsubscribe_tokens_purpose_check,
    ADD  CONSTRAINT email_unsubscribe_tokens_purpose_check
         CHECK (purpose IN ('welcome'));

ALTER TABLE users
    DROP COLUMN IF EXISTS webhook_digest_unsubscribed_at;

COMMIT;
