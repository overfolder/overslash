DROP TABLE IF EXISTS email_unsubscribe_tokens;

ALTER TABLE users
    DROP COLUMN IF EXISTS welcome_emails_unsubscribed_at,
    DROP COLUMN IF EXISTS welcome_email_sent_at;
