ALTER TABLE connections
    ADD COLUMN integration_managed boolean NOT NULL DEFAULT false;
