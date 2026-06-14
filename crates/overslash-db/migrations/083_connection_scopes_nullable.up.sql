-- Make `connections.scopes` nullable so it can represent "scopes unknown"
-- distinctly from "known to be empty". A white-label token import that omits
-- `scopes` stores NULL — Overslash doesn't know what the imported token was
-- granted, so the action scope-gate gives it the benefit of the doubt rather
-- than 403ing every scope-gated call. Orchestrated connections still record the
-- concrete granted set (possibly an empty array) from the token response.
ALTER TABLE connections
    ALTER COLUMN scopes DROP NOT NULL;

ALTER TABLE connections
    ALTER COLUMN scopes DROP DEFAULT;
