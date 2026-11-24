-- Per-org: may an IdP sign-in that reports no `auth_time` count its callback
-- time for the admin step-up?
--
-- D138 left such a session with no sign-in time (`auth_time_missing`), which
-- locks every admin of an org that signs in through Google without "Session
-- age claims" out of admin changes. An org can now accept the callback time
-- instead: its step-up then proves a fresh IdP round-trip, not a fresh
-- credential check. Read at gate time against the session's `created_at`
-- (the callback), so flipping it applies to live sessions too.
--
-- Default true: the lockout is the worse failure for most orgs; an org that
-- needs the strict reading turns it off.

ALTER TABLE orgs
    ADD COLUMN step_up_accept_callback_time BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN orgs.step_up_accept_callback_time IS
    'Admin step-up: an IdP sign-in with no auth_time counts its callback time (the session''s created_at) when true.';
