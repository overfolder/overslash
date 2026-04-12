-- User Signed Mode for the standalone secret-provide page.
--
-- Three additive columns, all nullable or defaulted so existing data is
-- unaffected and the migration is a pure extension:
--
-- 1. orgs.allow_unsigned_secret_provide — org-level toggle. When false,
--    every newly-minted secret_request is stamped require_user_session = true
--    at mint time, forcing the redemption to be backed by an oss_session
--    cookie in the same org. Defaults to TRUE so existing orgs keep their
--    current behavior.
--
-- 2. secret_requests.require_user_session — per-request capture of the org
--    policy at mint time. Forward-only: flipping the org toggle does NOT
--    retroactively invalidate URLs that were minted under the old policy.
--
-- 3. secret_versions.provisioned_by_user_id — the identity of the human
--    who actually pasted the value on the provide page, distinct from
--    secret_versions.created_by (which is the target identity that owns
--    the secret slot). NULL = anonymous URL fulfillment, populated when
--    the visitor had a same-org session cookie at submit time.

ALTER TABLE orgs
    ADD COLUMN allow_unsigned_secret_provide BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE secret_requests
    ADD COLUMN require_user_session BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE secret_versions
    ADD COLUMN provisioned_by_user_id UUID
        REFERENCES identities(id) ON DELETE SET NULL;

CREATE INDEX idx_secret_versions_provisioned_by
    ON secret_versions(provisioned_by_user_id)
    WHERE provisioned_by_user_id IS NOT NULL;
