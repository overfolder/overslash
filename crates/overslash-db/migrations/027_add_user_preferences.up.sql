ALTER TABLE identities
    ADD COLUMN preferences JSONB NOT NULL DEFAULT '{}'::jsonb;
