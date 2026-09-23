-- Automatic group provisioning from an external directory (OIDC `groups` claim).
--
-- A *directory group* is not a ceiling. It is a statement by the org's own IdP
-- about which humans belong together: it carries no grants, no rate limit and
-- no service visibility. That is why it lives here rather than as a fourth
-- class inside `groups` — see the D-NEXT entry in DECISIONS.md and
-- `docs/design/directory-group-sync.md`.
--
-- Three tables, one responsibility each:
--
--   * `directory_groups`          — what the directory said exists.
--   * `identity_directory_groups` — what the directory said about a human.
--     Sync owns this table outright and reconciles it to match the claim
--     exactly. It is deliberately NOT a `source` column on `identity_groups`:
--     keeping the two physically apart is what makes an authoritative sync
--     unable to delete an admin's manual assignment. Correctness by
--     construction rather than by every future writer remembering a filter.
--   * `group_directory_sources`   — the admin-owned edge that turns directory
--     membership into ceiling membership. Until an admin draws this edge a
--     directory group confers nothing, so discovering a group is never the
--     same act as granting it anything.
--
-- Effective membership is therefore `identity_groups` UNION (the groups
-- reachable through one `group_directory_sources` hop). Exactly one hop: no
-- recursion, no cycles, and the Layer 1 ceiling query stays a flat join.

-- What the directory says exists.
CREATE TABLE directory_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- The IdP config whose login produced this row. Nullable because the
    -- later non-login sources (Google Admin SDK, SCIM) have no
    -- `org_idp_configs` row to point at; they will write the same table with
    -- a different `source`.
    idp_config_id UUID REFERENCES org_idp_configs(id) ON DELETE CASCADE,
    source TEXT NOT NULL DEFAULT 'oidc_claim'
        CHECK (source IN ('oidc_claim')),
    -- The claim value, verbatim. Stable across renames — Entra sends group
    -- object GUIDs here, Okta sends names.
    external_id TEXT NOT NULL,
    -- Last label we saw. Equals `external_id` when the claim is a bare string.
    display_name TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Keyed on org + source rather than on `idp_config_id`, so that when a
    -- second source starts reporting the same group it lands on its own row
    -- instead of fighting the first over `display_name`.
    UNIQUE (org_id, source, external_id)
);

CREATE INDEX idx_directory_groups_org ON directory_groups(org_id);
CREATE INDEX idx_directory_groups_idp_config ON directory_groups(idp_config_id);

-- What the directory says about a human. Sync-owned and reconciled to match
-- the claim exactly; never written by hand.
CREATE TABLE identity_directory_groups (
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    directory_group_id UUID NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (identity_id, directory_group_id)
);

CREATE INDEX idx_identity_directory_groups_identity ON identity_directory_groups(identity_id);
CREATE INDEX idx_identity_directory_groups_group ON identity_directory_groups(directory_group_id);

-- The admin-owned edge: members of this directory group are members of this
-- Overslash group. Many-to-many on purpose — two directory groups can feed one
-- ceiling, and one directory group can feed several.
--
-- System groups are not valid targets. Myself membership is fixed by spec, and
-- Admins membership is held in lockstep with `identities.is_org_admin`, so an
-- IdP claim must not be able to desynchronise it or mint an org admin. That
-- rule is enforced in the handler (it spans two tables) and covered by tests.
CREATE TABLE group_directory_sources (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    directory_group_id UUID NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, directory_group_id)
);

CREATE INDEX idx_group_directory_sources_directory_group
    ON group_directory_sources(directory_group_id);

-- Per-IdP sync configuration.
--
-- Off by default: an existing org's logins are unchanged until an admin opts
-- in. `group_claim` is configurable because there is no agreement across IdPs
-- — Okta and Entra both use `groups` (names vs object GUIDs), while Auth0
-- needs a namespaced claim such as `https://acme.com/groups`.
--
-- Deliberately per-IdP-config rather than per-org: only an org's *own* IdP may
-- speak about that org's group structure (D12 — each IdP is its own trust
-- domain). A `groups` claim arriving from the shared Overslash-managed Google
-- or GitHub client says nothing about this org and is never synced.
ALTER TABLE org_idp_configs
    ADD COLUMN group_sync_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN group_claim TEXT NOT NULL DEFAULT 'groups';

-- The single definition of "which Layer 1 groups is this identity in".
--
-- A view rather than a CTE copied into each query: there are eight read sites
-- (the ceiling, service visibility, two service-name resolutions, the
-- connection re-auth check, group listing, member listing and member count)
-- and they have to agree exactly. A query that forgets the second arm silently
-- under-reports a directory-derived member — access that works on one surface
-- and 404s on another. One definition makes that class of drift impossible.
--
-- `UNION`, not `UNION ALL`: someone both assigned by hand and asserted by the
-- directory is one member, not two, or `count_members_in_group` double-counts.
--
-- Exactly one `group_directory_sources` hop. Directory groups cannot contain
-- each other, so this is not recursive and the ceiling query stays a flat join.
--
-- Writers do NOT go through here — `identity_groups` is still the only table
-- an admin's assignment lands in, and `identity_directory_groups` is still
-- owned outright by sync.
CREATE VIEW effective_identity_groups AS
    SELECT ig.identity_id, ig.group_id
      FROM identity_groups ig
    UNION
    SELECT idg.identity_id, gds.group_id
      FROM identity_directory_groups idg
      JOIN group_directory_sources gds
        ON gds.directory_group_id = idg.directory_group_id;
