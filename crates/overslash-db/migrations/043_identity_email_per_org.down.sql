-- Restore the pre-041 state. Only safe on fleets where every
-- `kind='user' AND email IS NOT NULL` row still has a unique email —
-- running this with multi-org data will fail with a unique-violation.
DROP INDEX IF EXISTS idx_identities_email_lookup;
CREATE UNIQUE INDEX idx_identities_user_email
    ON identities (email)
    WHERE kind = 'user' AND email IS NOT NULL;
