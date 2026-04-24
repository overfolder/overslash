-- `is_bootstrap` was a redundant label on top of the membership row itself.
-- The intent it captured — "this membership was created by POST /v1/orgs,
-- so it's a creator/admin membership backed by an Overslash-level IdP" —
-- is equally derivable from "the user has an admin membership AND their
-- `users.overslash_idp_*` columns are set". Removing the flag simplifies
-- the model and drops the "breakglass" UI concept along with it: the org's
-- creator is just an admin.
ALTER TABLE user_org_memberships DROP COLUMN IF EXISTS is_bootstrap;
