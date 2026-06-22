-- Re-point agent-level OAuth connections to their owner identity.
--
-- Connections used to bind to the *calling* identity, so an agent that
-- imported/connected a provider accreted a connection on itself. The
-- action-execution read path (D22) resolves connections at the OWNER identity
-- (identities.owner_id), so those agent-bound rows were invisible to it —
-- producing reauth loops (dev: the "main" agent held 4 leftover google
-- connections while the real one lived on the owner user).
--
-- This migration heals existing data to match the new write path (connections
-- bind to the owner on import/connect). It re-points every agent/sub_agent-owned
-- connection to its owner user, collapsing duplicates.
--
-- The idx_connections_one_default partial unique index — (identity_id,
-- provider_key) WHERE is_default — forces us to clear is_default before
-- re-pointing (so we never transiently create two defaults for one
-- (owner, provider)), then re-promote one per group afterwards (the 075 pattern).

-- 1. Owner wins: drop agent rows where the owner already holds a connection for
--    the same provider + account_email (NULL-safe match).
DELETE FROM connections c
USING identities i, connections oc
WHERE c.identity_id = i.id
  AND i.kind <> 'user' AND i.owner_id IS NOT NULL
  AND oc.identity_id = i.owner_id
  AND oc.provider_key = c.provider_key
  AND oc.account_email IS NOT DISTINCT FROM c.account_email
  AND oc.id <> c.id;

-- 2. Collapse agent-vs-agent dupes: among the remaining agent rows that map to
--    the same (owner, provider, account_email), keep only the most recent.
DELETE FROM connections c
USING identities i
WHERE c.identity_id = i.id
  AND i.kind <> 'user' AND i.owner_id IS NOT NULL
  AND c.id NOT IN (
    SELECT DISTINCT ON (i2.owner_id, c2.provider_key, c2.account_email) c2.id
    FROM connections c2 JOIN identities i2 ON c2.identity_id = i2.id
    WHERE i2.kind <> 'user' AND i2.owner_id IS NOT NULL
    ORDER BY i2.owner_id, c2.provider_key, c2.account_email, c2.created_at DESC
  );

-- 3. Clear is_default on the rows about to move, so step 4 can't transiently
--    create two defaults for one (owner, provider) and trip the unique index.
UPDATE connections c SET is_default = false
FROM identities i
WHERE c.identity_id = i.id AND i.kind <> 'user' AND i.owner_id IS NOT NULL;

-- 4. Re-point to the owner.
UPDATE connections c SET identity_id = i.owner_id, updated_at = now()
FROM identities i
WHERE c.identity_id = i.id AND i.kind <> 'user' AND i.owner_id IS NOT NULL;

-- 5. Re-promote one default per (identity, provider) that now lacks one
--    (groups composed only of just-moved rows, which were all demoted in step 3).
UPDATE connections SET is_default = true
WHERE id IN (
  SELECT DISTINCT ON (identity_id, provider_key) id
  FROM connections c
  WHERE NOT EXISTS (
    SELECT 1 FROM connections d
    WHERE d.identity_id = c.identity_id
      AND d.provider_key = c.provider_key AND d.is_default
  )
  ORDER BY identity_id, provider_key, created_at DESC
);
