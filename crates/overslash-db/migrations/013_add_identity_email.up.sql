ALTER TABLE identities ADD COLUMN email TEXT;

CREATE INDEX idx_identities_email ON identities(email) WHERE email IS NOT NULL;

-- One account per email for user identities
CREATE UNIQUE INDEX idx_identities_user_email ON identities(email) WHERE kind = 'user' AND email IS NOT NULL;
