-- Welcome-email send marker + per-user unsubscribe state for non-transactional
-- email (TODO.md §1.1). Billing emails are exempt by policy and never gated
-- by `welcome_emails_unsubscribed_at`. `welcome_email_sent_at` is set after
-- the welcome send succeeds so re-entered provisioning paths (corp-org
-- returning member, second-IdP add) never re-trigger a welcome.

ALTER TABLE users
    ADD COLUMN welcome_email_sent_at          TIMESTAMPTZ,
    ADD COLUMN welcome_emails_unsubscribed_at TIMESTAMPTZ;

-- One row per outgoing non-transactional email. The `token` is the
-- unguessable URL-embedded value; UUID v4 gives ~122 bits of entropy which
-- is sufficient for an unsubscribe-only blast radius. `org_id` is captured
-- at mint time so the redemption endpoint can write an audit row in the
-- correct org without re-deriving it from membership (root → personal_org;
-- corp JIT → the corp org). `purpose` keeps the door open for additional
-- non-transactional email types without adding new tables.
CREATE TABLE email_unsubscribe_tokens (
    token       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL DEFAULT 'welcome',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    redeemed_at TIMESTAMPTZ,
    CONSTRAINT email_unsubscribe_tokens_purpose_check
        CHECK (purpose IN ('welcome'))
);

CREATE INDEX email_unsubscribe_tokens_user_id
    ON email_unsubscribe_tokens (user_id);
