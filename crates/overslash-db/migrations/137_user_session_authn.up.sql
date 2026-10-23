-- How each dashboard session was authenticated (CASA 3.3.1, 2.4.1).
--
-- Admin-class mutations in a shared org require a session that came from an
-- IdP the org signs in with, and that is fresh enough (`authenticated_at`).
-- A magic link proves control of a mailbox, not possession of the org's
-- second factor, so it no longer reaches those operations; the IdP's MFA is
-- the only path. See DECISIONS.md, "Admin-class mutations need a fresh IdP
-- sign-in".
--
-- Rows created before this migration keep NULLs: such a session still works
-- for everything except admin mutations in a shared org, where the dashboard
-- asks for a step-up sign-in once.
ALTER TABLE user_sessions
    -- `idp` (OAuth/OIDC sign-in), `magic_link`, `dev` (DEV_AUTH only).
    -- NULL = not recorded (pre-migration row, or a session restarted from a
    -- token that did not carry one).
    ADD COLUMN auth_method TEXT
        CHECK (auth_method IN ('idp', 'magic_link', 'dev')),
    -- `oauth_providers.key` for an `idp` sign-in.
    ADD COLUMN auth_provider TEXT,
    -- When the human last proved who they are. Set by a sign-in, kept by a
    -- switch-org re-scope (which is not a sign-in).
    ADD COLUMN authenticated_at TIMESTAMPTZ,
    -- The ID token's `amr` / `acr`, as the IdP asserted them. Recorded for
    -- the sessions list and audit evidence, not enforced: Google and GitHub
    -- do not reliably send them.
    ADD COLUMN idp_amr TEXT[],
    ADD COLUMN idp_acr TEXT,
    ADD CONSTRAINT user_sessions_idp_has_provider
        CHECK (auth_method IS DISTINCT FROM 'idp' OR auth_provider IS NOT NULL);
