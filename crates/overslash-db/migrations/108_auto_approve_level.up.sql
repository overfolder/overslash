-- Auto-approval becomes a level, not a boolean.
--
-- A grant has always carried two independent things: `access_level` — may
-- this run at all? — and `auto_approve_reads` — may it run without a human?
-- The second was pinned to reads, so the only expressible policy was "reads
-- are free, everything else waits for an approval". That is the right
-- default, but it left no way to say "this group may write to the scratch
-- Jira project unattended" short of turning approvals off wholesale.
--
-- `auto_approve_level` puts auto-approval on the same read < write < admin
-- ladder as `access_level`, as a second ceiling bounded by the first:
--
--     access_level        read ──── write ──── admin
--     auto_approve_level  none ─ read ─ write ─ admin   (must be <= access)
--
-- The backfill is behaviour-preserving: auto_approve_reads = true is exactly
-- auto_approve_level = 'read'.
--
-- `auto_approve_reads` stays for one release as a deprecated API alias. The
-- API keeps it coherent on write (level != 'none'), but it is no longer the
-- source of truth for any decision — read `auto_approve_level`.

ALTER TABLE group_grants
  ADD COLUMN auto_approve_level TEXT NOT NULL DEFAULT 'none';

UPDATE group_grants SET auto_approve_level = 'read' WHERE auto_approve_reads;

ALTER TABLE group_grants
  ADD CONSTRAINT group_grants_auto_approve_level_valid
    CHECK (auto_approve_level IN ('none', 'read', 'write', 'admin')),
  ADD CONSTRAINT group_grants_auto_approve_within_ceiling
    CHECK (auto_approve_level = 'none'
        OR access_level = 'admin'
        OR (access_level = 'write' AND auto_approve_level IN ('read', 'write'))
        OR (access_level = 'read'  AND auto_approve_level = 'read'));

COMMENT ON COLUMN group_grants.auto_approve_level IS
  'How far up the read<write<admin ladder actions skip Layer 2 (no permission rule, no approval). ''none'' = always require approval. Bounded by access_level.';

COMMENT ON COLUMN group_grants.auto_approve_reads IS
  'DEPRECATED — derived mirror of (auto_approve_level <> ''none''). Read auto_approve_level instead; this column is dropped once the API alias is removed.';
