-- "One actor per human per org" — the rule migration 040 was designed around
-- and 043 cites as its reason for dropping the global email UNIQUE, but which
-- no migration ever created. 040 added only the plain `idx_identities_user`.
--
-- Three code sites already assume it exists:
--   * `repos::identity::find_by_org_and_user` — "At most one row exists"
--   * `repos::identity::lifecycle::remove_user` — detaches `user_id` on
--     archive specifically to free the index slot for a re-invite
--   * migration 043's own rationale
-- and it is specified at `docs/design/multi_org_auth.md` §Schema.
--
-- Without it a fork is silent rather than rejected, and `find_by_org_and_user`
-- is a `fetch_optional` over the duplicates: it returns whichever row the
-- planner emits first and discards the rest. That row decides the `sub` in the
-- session JWT on org switch, the connect-gate account match, the OAuth consent
-- target and billing ownership — so a duplicate makes all four planner-order
-- dependent.

-- 1. Heal any existing duplicates before constraining. Keep the oldest live
--    row per (org, human) — it is the one that accumulated the agents, grants
--    and audit history, the same "oldest wins" tie-break `find_child_by_name`
--    uses — and detach the rest.
--
--    Detach, not delete: `user_id = NULL` is exactly what `remove_user` does
--    when archiving a member, so the losing rows keep their subtree, their
--    audit trail and their own `external_id`. They simply stop claiming to be
--    this human's actor, which is what the duplicate was lying about. An org
--    admin can archive them from the Members page afterwards.
UPDATE identities i
   SET user_id = NULL, updated_at = now()
 WHERE i.kind = 'user'
   AND i.user_id IS NOT NULL
   AND i.id <> (
     SELECT keep.id
       FROM identities keep
      WHERE keep.org_id = i.org_id
        AND keep.user_id = i.user_id
        AND keep.kind = 'user'
      ORDER BY (keep.archived_at IS NOT NULL), keep.created_at, keep.id
      LIMIT 1
   );

-- 2. The constraint itself. Partial on both columns: `user_id IS NULL` covers
--    pre-created invites and name-based impersonation rows (many per org, all
--    legitimately unlinked), and agents/sub-agents never carry a `user_id`.
CREATE UNIQUE INDEX identities_org_user_unique
    ON identities (org_id, user_id)
    WHERE user_id IS NOT NULL AND kind = 'user';

-- 3. Drop the duplicate email index. Migration 043 recreated the email index
--    as `idx_identities_email_lookup` believing it had to replace a UNIQUE it
--    could not ALTER — but the index it dropped was `idx_identities_user_email`
--    (013's UNIQUE), while 013's plain `idx_identities_email` had been there
--    all along with an identical definition. Two byte-identical indexes on
--    `identities(email) WHERE email IS NOT NULL`; keep the older name.
DROP INDEX IF EXISTS idx_identities_email_lookup;
