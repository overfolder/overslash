UPDATE connections SET scopes = '{}'::text[] WHERE scopes IS NULL;

ALTER TABLE connections
    ALTER COLUMN scopes SET DEFAULT '{}'::text[];

ALTER TABLE connections
    ALTER COLUMN scopes SET NOT NULL;
