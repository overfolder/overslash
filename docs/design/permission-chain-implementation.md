# Permission Chain Walk & Approval Bubbling — Implementation Design

**Status**: Not Implemented (Phase 3)
**Date**: 2026-03-29
**Depends on**: Phase 1 (flat permissions, approvals), Phase 2 (OAuth, service registry)
**Related**: [overslash.md](overslash.md) (core design), [SPEC.md](../../SPEC.md) Section 5

---

## 1. Overview

Overslash currently checks permissions at a single identity level. The spec defines a hierarchical model: User → Agent → SubAgent chains where every level must authorize an action. This document specifies how to implement:

- **Identity hierarchy** with parent/child relationships and depth tracking
- **Permission chain walk** that traverses the ancestor chain bottom-to-top
- **`inherit_permissions`** as a live pointer (not a copied rule set)
- **Approval bubbling** where gaps create approvals resolvable by ancestors
- **Approval visibility scoping** (`actionable` vs `mine`)
- **Webhook enrichment** with `gap_identity` and `can_be_handled_by`

The design is fully backwards-compatible. Existing flat identities continue to work unchanged — hierarchy is opt-in.

---

## 2. Data Model Changes

### Migration 016: `identity_hierarchy_and_approval_bubbling`

#### 2.1 Identities Table

```sql
-- Expand kind to include subagent
ALTER TABLE identities DROP CONSTRAINT identities_kind_check;
ALTER TABLE identities ADD CONSTRAINT identities_kind_check
    CHECK (kind IN ('user', 'agent', 'subagent'));

-- Hierarchy columns
ALTER TABLE identities ADD COLUMN parent_id UUID REFERENCES identities(id) ON DELETE CASCADE;
ALTER TABLE identities ADD COLUMN owner_id UUID REFERENCES identities(id) ON DELETE SET NULL;
ALTER TABLE identities ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;
ALTER TABLE identities ADD COLUMN inherit_permissions BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE identities ADD COLUMN can_create_sub BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE identities ADD COLUMN max_sub_depth INTEGER;
ALTER TABLE identities ADD COLUMN ttl INTERVAL;

-- Indexes for hierarchy traversal
CREATE INDEX idx_identities_parent ON identities(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_identities_owner ON identities(owner_id) WHERE owner_id IS NOT NULL;
```

**Backwards compatibility**: All new columns have defaults or are nullable. Existing rows get `parent_id=NULL, depth=0, inherit_permissions=false`. These identities enter the single-level flat check path (no chain walk), producing identical behavior to today.

#### 2.2 Approvals Table

```sql
-- Identity where the permission gap was detected
ALTER TABLE approvals ADD COLUMN gap_identity_id UUID REFERENCES identities(id) ON DELETE CASCADE;

-- Ancestor identity IDs that can resolve this approval
ALTER TABLE approvals ADD COLUMN can_be_handled_by UUID[] NOT NULL DEFAULT '{}';

-- For allow_remember: which identity receives the new rule
ALTER TABLE approvals ADD COLUMN grant_to UUID REFERENCES identities(id) ON DELETE SET NULL;
```

**Backwards compatibility**: Existing approvals get `gap_identity_id=NULL, can_be_handled_by='{}'`. The resolution path falls back to current behavior (any org-level key can resolve).

#### 2.3 Permission Rules Table

```sql
-- Optional expiry for rules created via allow_remember with expires_in
ALTER TABLE permission_rules ADD COLUMN expires_at TIMESTAMPTZ;

CREATE INDEX idx_permission_rules_expires ON permission_rules(expires_at)
    WHERE expires_at IS NOT NULL;
```

#### 2.4 Down Migration

```sql
-- permission_rules
DROP INDEX IF EXISTS idx_permission_rules_expires;
ALTER TABLE permission_rules DROP COLUMN IF EXISTS expires_at;

-- approvals
ALTER TABLE approvals DROP COLUMN IF EXISTS grant_to;
ALTER TABLE approvals DROP COLUMN IF EXISTS can_be_handled_by;
ALTER TABLE approvals DROP COLUMN IF EXISTS gap_identity_id;

-- identities
DROP INDEX IF EXISTS idx_identities_owner;
DROP INDEX IF EXISTS idx_identities_parent;
ALTER TABLE identities DROP COLUMN IF EXISTS ttl;
ALTER TABLE identities DROP COLUMN IF EXISTS max_sub_depth;
ALTER TABLE identities DROP COLUMN IF EXISTS can_create_sub;
ALTER TABLE identities DROP COLUMN IF EXISTS inherit_permissions;
ALTER TABLE identities DROP COLUMN IF EXISTS depth;
ALTER TABLE identities DROP COLUMN IF EXISTS owner_id;
ALTER TABLE identities DROP COLUMN IF EXISTS parent_id;
ALTER TABLE identities DROP CONSTRAINT identities_kind_check;
ALTER TABLE identities ADD CONSTRAINT identities_kind_check
    CHECK (kind IN ('user', 'agent'));
DELETE FROM identities WHERE kind = 'subagent';
```

---

## 3. Chain Walk Algorithm

### 3.1 Data Structures

```rust
/// Result of hierarchical permission resolution.
pub enum ChainWalkResult {
    /// All levels in the chain allow the action.
    Allowed,
    /// One or more levels have gaps requiring approval.
    NeedsApproval(Vec<PermissionGap>),
    /// Explicitly denied at some level.
    Denied(String),
}

/// A gap detected during chain walk.
pub struct PermissionGap {
    /// The identity level where the gap was found.
    pub gap_identity_id: Uuid,
    /// Display name of the gap identity (for webhooks/UI).
    pub gap_identity_name: String,
    /// Permission keys not covered at this level.
    pub uncovered_keys: Vec<PermissionKey>,
    /// IDs of all ancestors above the gap (who can resolve).
    pub can_be_handled_by: Vec<Uuid>,
}
```

### 3.2 Pseudocode

```
fn resolve_chain(
    ancestor_chain: Vec<Identity>,           // ordered root-to-leaf (includes executing identity)
    rules_by_identity: HashMap<Uuid, Vec<PermissionRule>>,
    keys: Vec<PermissionKey>,
) -> ChainWalkResult:

    let mut gaps = vec![];

    // Walk from leaf (executing identity) toward root
    for (i, identity) in ancestor_chain.iter().rev().enumerate():
        let rules = rules_by_identity.get(&identity.id).unwrap_or_default()
        let active_rules = rules.iter()
            .filter(|r| r.expires_at.is_none() || r.expires_at > now())

        // 1. Check for explicit denies first — deny at ANY level blocks everything
        for key in &keys:
            for rule in active_rules where rule.effect == Deny:
                if glob_match(&rule.action_pattern, &key.0):
                    return Denied(format!("denied by rule at {}", identity.name))

        // 2. Check allow coverage
        let uncovered: Vec<_> = keys.iter()
            .filter(|k| !active_rules.any(|r| r.effect == Allow && glob_match(&r.action_pattern, &k.0)))
            .collect()

        if uncovered.is_empty():
            // Fully covered by explicit rules — this level passes
            continue

        if identity.inherit_permissions && identity.parent_id.is_some():
            // This level inherits from parent. The parent's rules will be
            // checked when we reach the parent level in the loop.
            // This is the "live pointer" — we don't copy rules, we just
            // skip this level and let the parent's check cover it.
            continue

        // 3. GAP — not covered and not inheriting
        // Ancestors = all identities above this one in the chain
        let ancestors: Vec<Uuid> = ancestor_chain[..ancestor_chain.len() - 1 - i]
            .iter().map(|a| a.id).collect()

        gaps.push(PermissionGap {
            gap_identity_id: identity.id,
            gap_identity_name: identity.name.clone(),
            uncovered_keys: uncovered,
            can_be_handled_by: ancestors,
        })

    if gaps.is_empty():
        Allowed
    else:
        NeedsApproval(gaps)
```

### 3.3 Entry Point (in `execute_action` handler)

```
fn execute_action(identity_id, action_request):
    let identity = get_identity(identity_id)

    if identity.parent_id.is_none():
        // Legacy flat identity — use existing single-level check
        let rules = list_by_identity(identity_id)
        return check_permissions(rules, keys)  // existing function, unchanged

    // Hierarchical identity — chain walk
    let chain = get_ancestor_chain(identity_id)   // recursive CTE, root-to-leaf
    let all_ids = chain.iter().map(|i| i.id).collect()
    let all_rules = list_by_identities(all_ids)   // batch load
    let rules_map = group_by_identity(all_rules)

    return resolve_chain(chain, rules_map, keys)
```

### 3.4 Edge Cases

| Scenario | Behavior |
|----------|----------|
| **Flat identity (no parent)** | Falls through to existing `check_permissions`. No chain walk. |
| **User at root with no rules** | Gap at user level. `can_be_handled_by` is empty — only org-level keys can resolve. |
| **Cascading inheritance** | SubAgent inherits → Agent inherits → User has rules. Both SubAgent and Agent are skipped; User's rules cover all three levels. |
| **Partial inheritance** | SubAgent inherits from Agent. Agent has rules covering `GET:*` but not `POST:*`. SubAgent's `POST` is uncovered at Agent level → gap at Agent. |
| **Deny at any level** | Deny rule at User level blocks SubAgent even if SubAgent has allow rules. Deny short-circuits. |
| **Multiple gaps** | Agent at depth=1 has no rules (gap). SubAgent at depth=2 also has no rules and doesn't inherit (gap). Two approvals created. |
| **inherit_permissions at root** | If a User has `inherit_permissions=true` but no parent, inheritance is a no-op. The user's own rules (or lack thereof) determine the outcome. |
| **Expired rules** | Rules with `expires_at` in the past are filtered out before checking. |

### 3.5 Ancestor Chain Query

```sql
WITH RECURSIVE ancestors AS (
    SELECT id, org_id, name, kind, parent_id, owner_id, depth,
           inherit_permissions, can_create_sub, max_sub_depth, ttl,
           metadata, external_id, created_at, updated_at
    FROM identities WHERE id = $1
    UNION ALL
    SELECT i.id, i.org_id, i.name, i.kind, i.parent_id, i.owner_id, i.depth,
           i.inherit_permissions, i.can_create_sub, i.max_sub_depth, i.ttl,
           i.metadata, i.external_id, i.created_at, i.updated_at
    FROM identities i
    JOIN ancestors a ON i.id = a.parent_id
)
SELECT * FROM ancestors ORDER BY depth ASC;
```

Returns identities ordered root-to-leaf. For a SubAgent at depth=2, this returns: `[User(depth=0), Agent(depth=1), SubAgent(depth=2)]`.

### 3.6 Batch Rule Loading

```sql
SELECT * FROM permission_rules
WHERE identity_id = ANY($1)
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY identity_id;
```

Single query loads active rules for the entire chain.

---

## 4. API Changes

### 4.1 Identity CRUD

**`POST /v1/identities`** — extended request:

```json
{
  "name": "researcher",
  "kind": "subagent",
  "parent_id": "idt_henry",
  "inherit_permissions": true,
  "can_create_sub": false,
  "max_sub_depth": 3,
  "ttl": "2h"
}
```

Validation:
- If `parent_id` is provided: parent must exist in same org, parent's `can_create_sub` must be true (or caller is the parent itself), `depth = parent.depth + 1`, depth must not exceed parent's `max_sub_depth`
- `owner_id` is computed: if parent is a user, `owner_id = parent.id`; otherwise `owner_id = parent.owner_id`
- `kind` must match depth: `user` at 0, `agent` at 1, `subagent` at 2+

**`GET /v1/identities`** — response extended with hierarchy fields:

```json
{
  "id": "idt_...",
  "name": "researcher",
  "kind": "subagent",
  "parent_id": "idt_henry",
  "owner_id": "idt_alice",
  "depth": 2,
  "inherit_permissions": true,
  "can_create_sub": false
}
```

### 4.2 Approval Resolution

**`POST /v1/approvals/{id}/resolve`** — extended request:

```json
{
  "decision": "allow_remember",
  "grant_to": "idt_henry",
  "expires_in": "30d"
}
```

Changes:
- **Authorization check**: If `gap_identity_id` is set, the resolver must be in `can_be_handled_by`. Self-approval (resolver == gap identity) is forbidden (403).
- **`grant_to`**: Which identity receives the permission rule. Must be the gap identity or an ancestor in the chain. Defaults to `gap_identity_id` if omitted.
- **`expires_in`**: Parsed as duration, sets `expires_at` on the created permission rule.

### 4.3 Approval Listing

**`GET /v1/approvals`** — new `scope` query parameter:

| Scope | SQL condition | Meaning |
|-------|--------------|---------|
| `actionable` | `$1 = ANY(can_be_handled_by)` | Approvals I can resolve (descendants' gaps) |
| `mine` | `identity_id = $1` | Approvals about my own actions |
| `all` (default) | `identity_id = $1 OR $1 = ANY(can_be_handled_by)` | Both |

For legacy approvals where `can_be_handled_by` is empty, `scope=actionable` falls back to org-level visibility (same as today).

### 4.4 Action Execution Response

**`POST /v1/actions/execute`** — `pending_approval` response extended:

```json
{
  "status": "pending_approval",
  "approval_id": "apr_...",
  "approval_url": "/approve/{token}",
  "action_description": "Create pull request 'Fix bug' on acme/app",
  "expires_at": "2026-03-29T12:00:00Z",
  "gaps": [
    {
      "approval_id": "apr_...",
      "gap_identity": "henry/researcher",
      "gap_identity_id": "idt_...",
      "can_be_handled_by": ["idt_henry", "idt_alice"]
    }
  ]
}
```

For single-gap cases (the common case), `approval_id` points to the only approval. For multi-gap cases, `gaps` lists all of them. The `approval_id` at the top level is the first/primary gap.

---

## 5. Webhook Payload Changes

### 5.1 `approval.created` (new event — currently not dispatched)

```json
{
  "approval_id": "apr_...",
  "status": "pending",
  "action_summary": "Create pull request 'Fix bug' on acme/app",
  "identity_id": "idt_researcher",
  "gap_identity": "henry/researcher",
  "gap_identity_id": "idt_researcher",
  "can_be_handled_by": ["idt_henry", "idt_alice"],
  "expires_at": "2026-03-29T12:00:00Z"
}
```

### 5.2 `approval.resolved` (existing — fields added)

```json
{
  "approval_id": "apr_...",
  "status": "allowed",
  "action_summary": "Create pull request 'Fix bug' on acme/app",
  "gap_identity_id": "idt_researcher",
  "resolved_by": "idt_alice",
  "grant_to": "idt_henry"
}
```

New fields: `gap_identity_id`, `resolved_by`, `grant_to` (only when `allow_remember`).

---

## 6. Migration Strategy

### 6.1 Backwards Compatibility (Zero-Downtime)

The migration is additive — no existing columns are modified or removed.

| Existing data | New column defaults | Behavior |
|---------------|-------------------|----------|
| Identities (users, agents) | `parent_id=NULL, depth=0, inherit=false` | Single-level flat check (no chain walk) |
| Approvals | `gap_identity_id=NULL, can_be_handled_by='{}'` | Any org-level key can resolve |
| Permission rules | `expires_at=NULL` | Rules never expire (same as today) |

### 6.2 Gradual Adoption

1. **Deploy migration 016** — schema changes only, no behavior change
2. **Deploy Rust type + repo updates** — code compiles with new fields, but `execute_action` still uses flat check for all identities (since all have `parent_id=NULL`)
3. **Deploy chain walk** — new code path activated only when `parent_id IS NOT NULL`
4. **Users create hierarchical identities** — first agent created with `parent_id` enters the chain walk path

No feature flag needed. The `parent_id=NULL` check in `execute_action` is the natural feature gate.

### 6.3 No Data Migration

Existing identities are not retroactively placed into hierarchies. Users manually set up parent/child relationships for new or existing identities through the API or dashboard.

---

## 7. Implementation Order

Steps are ordered by dependency. Each step produces a compilable intermediate state.

| Step | What | Key files | Depends on |
|------|------|-----------|------------|
| 1 | Migration 016 | `migrations/016_*.sql` | — |
| 2 | Rust type updates | `types/identity.rs`, `types/approval.rs` | Step 1 |
| 3 | Identity repo functions | `repos/identity.rs`, `repos/permission_rule.rs` | Step 2 |
| 4 | Chain walk algorithm | `permissions.rs` | Step 2 |
| 5 | Identity CRUD API | `routes/identities.rs` | Step 3 |
| 6 | Action execution integration | `routes/actions.rs` | Steps 3, 4 |
| 7 | Approval resolution + scoping | `routes/approvals.rs`, `repos/approval.rs` | Step 6 |
| 8 | Webhook payload updates | `routes/actions.rs`, `routes/approvals.rs` | Step 7 |
| 9 | Dashboard: hierarchy + approvals UI | `dashboard/` | Steps 5, 7 |

### Rust Type Changes (Step 2 detail)

**`IdentityKind`**: Add `SubAgent` variant. Update `as_str()` / `FromStr` / `Display`.

**`Identity`**: Add `parent_id: Option<Uuid>`, `owner_id: Option<Uuid>`, `depth: i32`, `inherit_permissions: bool`, `can_create_sub: bool`, `max_sub_depth: Option<i32>`, `ttl: Option<Duration>`.

**`Approval`**: Add `gap_identity_id: Option<Uuid>`, `can_be_handled_by: Vec<Uuid>`, `grant_to: Option<Uuid>`.

**`IdentityRow`** / **`ApprovalRow`**: Mirror the same field additions. Update all SQL SELECT lists in existing repo queries.

### Identity Repo Functions (Step 3 detail)

- `get_ancestor_chain(pool, identity_id) -> Vec<IdentityRow>` — recursive CTE (Section 3.5)
- `is_ancestor_of(pool, potential_ancestor_id, descendant_id) -> bool` — via ancestor chain
- `create_sub_identity(pool, CreateSubIdentity) -> IdentityRow` — computes depth/owner_id, validates constraints
- `list_children(pool, parent_id) -> Vec<IdentityRow>` — `WHERE parent_id = $1`
- `cleanup_expired_sub_identities(pool) -> u64` — `WHERE ttl IS NOT NULL AND created_at + ttl < now()`
- `list_by_identities(pool, identity_ids) -> Vec<PermissionRuleRow>` — batch load with expiry filter (Section 3.6)

---

## 8. Test Plan

### 8.1 Unit Tests (`crates/overslash-core/src/permissions.rs`)

| # | Test | Expected |
|---|------|----------|
| 1 | Flat identity (no parent, no chain) | Same result as existing `check_permissions` |
| 2 | Two-level: user has rules, agent inherits | `Allowed` |
| 3 | Two-level: agent has no rules, no inherit | `NeedsApproval` with gap at agent |
| 4 | Three-level: gap at middle (agent) | Gap at agent, `can_be_handled_by = [user]` |
| 5 | Deny at any level | `Denied` even if other levels allow |
| 6 | Multiple gaps in chain | Two `PermissionGap` entries |
| 7 | Cascading inherit through 3 levels | All skip to root, `Allowed` if root has rules |
| 8 | Expired rules filtered out | Rule with past `expires_at` ignored, gap detected |

### 8.2 Integration Tests (`crates/overslash-api/tests/`)

| # | Test | Expected |
|---|------|----------|
| 9 | Create sub-identity with parent_id | Correct `depth`, `owner_id`, `kind` |
| 10 | Depth limit enforcement | 400 when exceeding `max_sub_depth` |
| 11 | Execute action as subagent, gap detected | 202 with `gap_identity_id` and `can_be_handled_by` |
| 12 | Self-approval attempt | 403 forbidden |
| 13 | Ancestor resolves approval | 200. Unrelated identity gets 403. |
| 14 | `scope=actionable` filtering | Only shows gaps where caller is ancestor |
| 15 | `scope=mine` filtering | Only shows approvals where caller is executing identity |
| 16 | `allow_remember` with `grant_to` | Permission rule created on target identity |
| 17 | `allow_remember` with `expires_in` | Permission rule has correct `expires_at` |
| 18 | Webhook includes new fields | `gap_identity_id` and `can_be_handled_by` in payload |
| 19 | Legacy flat identity | Unchanged 200/202 behavior, no chain walk |
| 20 | TTL cleanup | Sub-identity deleted after TTL expires |

### 8.3 Dashboard Tests

| # | Test | Expected |
|---|------|----------|
| 21 | Identity hierarchy tree renders | Parent/child relationships shown as tree |
| 22 | Approval scope tabs work | Switching actionable/mine filters correctly |
| 23 | Resolve approval from dashboard | grant_to picker, expires_in picker functional |
