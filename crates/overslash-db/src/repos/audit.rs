use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct AuditRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub detail: serde_json::Value,
    pub description: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: OffsetDateTime,
    /// Set when the request was made via `X-Overslash-As` impersonation.
    /// Records the service-account identity that performed the impersonation;
    /// `identity_id` is the effective (impersonated) identity.
    pub impersonated_by_identity_id: Option<Uuid>,
    /// System-derived metadata tags (`sql:write`, `table:wh/orders`,
    /// `service:metabase`, `outcome:error`, …). Searchable via
    /// `GET /v1/audit?tag=`. Empty for events outside the action/approval
    /// path — see `log_tagged`.
    pub tags: Vec<String>,
    /// `identity_id`'s name **as of write time** (D59). Historical on purpose:
    /// the row records the name the actor had when they acted. NULL when the
    /// event had no actor, or for rows written before migration 110 whose
    /// identity had already been hard-deleted.
    pub actor_name: Option<String>,
    /// Name of the **root user** of the actor's identity chain as of write
    /// time — the human at the top, not the direct `owner_id` parent, so a
    /// sub-agent's row resolves to the same person the audit table's User
    /// column shows.
    pub owner_user_name: Option<String>,
}

pub struct AuditEntry<'a> {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub action: &'a str,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<Uuid>,
    pub detail: serde_json::Value,
    pub description: Option<&'a str>,
    pub ip_address: Option<&'a str>,
}

/// Insert an audit row. `impersonated_by_identity_id` is passed separately
/// so callers (handlers) never need to set it — `OrgScope::log_audit`
/// injects it automatically from the scope's impersonation context.
pub(crate) async fn log(
    pool: &PgPool,
    entry: &AuditEntry<'_>,
    impersonated_by_identity_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    log_tagged(pool, entry, impersonated_by_identity_id, &[]).await
}

/// Insert an audit row carrying system-derived metadata tags.
///
/// Kept separate from [`log`] — and taking the tags as an argument rather than
/// a field on [`AuditEntry`] — because tags are minted on exactly one code
/// path (the gated action call and the approval lifecycle around it) while
/// `AuditEntry` is constructed at over a hundred sites. A field would have
/// meant `tags: vec![]` at every one of them to say nothing.
pub(crate) async fn log_tagged(
    pool: &PgPool,
    entry: &AuditEntry<'_>,
    impersonated_by_identity_id: Option<Uuid>,
    tags: &[String],
) -> Result<(), sqlx::Error> {
    // The actor's name and their root user's are resolved inside the INSERT
    // rather than by a second round trip: `log_audit` is called from over a
    // hundred sites on the hottest write path in the system, and every one of
    // them has an `identity_id` and nothing else. The recursive walk is a
    // handful of primary-key lookups (a sub-agent is two hops from its human);
    // `depth < 10` is a cycle backstop, `owner_id` being an application-
    // maintained pointer rather than a constrained tree.
    //
    // Both names come out NULL when there is no actor or the identity is gone,
    // which is what the LEFT JOIN they replace produced. See D59 for why the
    // row keeps the *historical* name.
    sqlx::query!(
        "WITH RECURSIVE chain AS (
             SELECT id, org_id, owner_id, kind, name, 1 AS depth
               FROM identities WHERE id = $2 AND org_id = $1
             UNION ALL
             SELECT i.id, i.org_id, i.owner_id, i.kind, i.name, c.depth + 1
               FROM identities i
               JOIN chain c ON i.id = c.owner_id AND i.org_id = c.org_id
              WHERE c.depth < 10
         )
         INSERT INTO audit_log (org_id, identity_id, action, resource_type, resource_id, detail, description, ip_address, impersonated_by_identity_id, tags, actor_name, owner_user_name)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                (SELECT name FROM chain WHERE id = $2),
                (SELECT name FROM chain WHERE kind = 'user' ORDER BY depth DESC LIMIT 1)",
        entry.org_id,
        entry.identity_id,
        entry.action,
        entry.resource_type,
        entry.resource_id,
        entry.detail,
        entry.description,
        entry.ip_address,
        impersonated_by_identity_id,
        tags,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Clone, Default)]
pub struct AuditFilter {
    pub org_id: Uuid,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub identity_id: Option<Uuid>,
    pub since: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    /// Free-text terms matched (case-insensitively) against `action`,
    /// `description`, and `actor_name`. Every term must match at least one of
    /// those columns — AND, not OR, because each text bubble in the search bar
    /// narrows, exactly like `tags`. Powers the audit log search bar's text
    /// bubbles.
    ///
    /// All three are `audit_log` columns since migration 110. That is what
    /// makes the predicate indexable at all: while the actor name was read
    /// through a join, no index on this table could serve it (D59).
    pub q_terms: Option<Vec<String>>,
    /// Exact match on `audit_log.id`. Used by the dashboard deep-link
    /// (`/audit?event=<uuid>`) to confirm a target event exists outside the
    /// active filter set.
    pub event_id: Option<Uuid>,
    /// Match a UUID across the row id, actor id, resource id, and the JSONB
    /// `detail` keys `execution_id` / `replayed_from_approval`. Powers the
    /// `uuid =` search bar key.
    pub uuid: Option<Uuid>,
    // ── Per-column `~` (contains) + `=` (match) filters. Each powers a
    // search-bar key; substrings are matched case-insensitively (ILIKE).
    /// Substring on `action`. Powers `event ~`.
    pub action_contains: Option<String>,
    /// Substring on `resource_type`. Powers `resource ~`.
    pub resource_type_contains: Option<String>,
    /// Exact / substring on `description`. Powers `description =` / `~`.
    pub description: Option<String>,
    pub description_contains: Option<String>,
    /// Exact / substring on `ip_address`. Powers `ip =` / `~`.
    pub ip_address: Option<String>,
    pub ip_address_contains: Option<String>,
    /// Substring on the actor's recorded name (`actor_name`). Powers
    /// `agent ~` / `identity ~`. Matches the name the actor had at the time,
    /// which is also the name the audit table renders — see D59.
    pub identity_name_contains: Option<String>,
    /// Restrict the actor's identity kind (e.g. `['user']` or
    /// `['agent','sub_agent']`). Scopes the kind split for `agent`/`user`.
    pub identity_kinds: Option<Vec<String>>,
    /// Owning user (root of the actor's identity chain). Matches rows where the
    /// actor *is* this user (acting directly) or is one of the user's agents
    /// (`identities.owner_id`). Powers the `user =` search bar key — a wider
    /// match than the exact-actor `identity_id`, consistent with the audit
    /// table's "User" column.
    pub owner_user_id: Option<Uuid>,
    /// Substring (case-insensitive) on the recorded owning-user name — the
    /// actor's own name when they are a user, else the **root user** of their
    /// chain. Powers `user ~`. Root rather than direct parent since migration
    /// 109: a sub-agent's row used to match its parent *agent's* name here,
    /// which agreed with neither this field's name nor the User column.
    pub owner_user_contains: Option<String>,
    /// Upstream result of execution events, matched against the normalized
    /// `detail.is_error` flag written by the action executors. `Some(true)`
    /// returns executions whose upstream reported failure (MCP `is_error`
    /// envelope, upstream HTTP >= 400); `Some(false)` returns executions that
    /// carry the flag and succeeded — rows without the flag (non-execution
    /// events, pre-flag history) match neither. Powers the `result =` key.
    pub is_error: Option<bool>,
    /// Require **all** of these metadata tags on the row (`tags @> $n`).
    /// AND rather than OR because tags narrow along independent axes — a
    /// `service:metabase` + `sql:write` filter means "writes against
    /// Metabase", which OR would turn into a far larger set. Powers `tag =`.
    pub tags: Option<Vec<String>>,
    /// Substring (case-insensitive) against any one tag. Powers `tag ~`, which
    /// is how you find `table:warehouse/orders` without knowing the db label.
    pub tag_contains: Option<String>,
    pub limit: i64,
    /// Keyset cursor: return rows strictly older than `(before, before_id)` in
    /// `(created_at DESC, id DESC)` order. `before_id` breaks ties between rows
    /// sharing a timestamp — rows written in one transaction share `now()`, so
    /// without it a cursor can skip or repeat them.
    ///
    /// Prefer this to `offset` for paging: `OFFSET n` walks `n + limit` index
    /// entries, so an infinite scroll costs O(pages²) over a session.
    pub before: Option<OffsetDateTime>,
    pub before_id: Option<Uuid>,
    /// Legacy offset pagination. Still honoured — `/v1/audit` is a public
    /// endpoint — but the dashboard uses `before`/`before_id`. Ignored in
    /// practice when a cursor is supplied, since the cursor has already
    /// excluded everything the offset would have skipped.
    pub offset: i64,
}

pub(crate) async fn query_filtered(
    pool: &PgPool,
    filter: &AuditFilter,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    // Build `%term%` patterns once so the query plan can short-circuit when a
    // filter is None.
    let q_likes = filter
        .q_terms
        .as_deref()
        .filter(|terms| !terms.is_empty())
        .map(|terms| terms.iter().map(|q| format!("%{q}%")).collect::<Vec<_>>());
    // One free-text term, promoted to a top-level predicate the trigram index
    // can serve. The `NOT EXISTS` below is the real filter, but the planner
    // cannot index it: the pattern is a correlated column of `unnest`, so it is
    // an anti-join subplan, evaluated per candidate row. Adding one redundant
    // conjunct over a single parameter gives the planner something to prune
    // with, and pruning is sound because the conjunct is a *superset* of the
    // real predicate — a row matching any single column matches the
    // concatenation, so this can only admit extra rows, which the `NOT EXISTS`
    // then rejects.
    //
    // The longest term, because selectivity is unknowable here and length is
    // the one available proxy. Under three characters there is no trigram to
    // look up, so the query keeps today's sequential filter.
    let q_prune = filter
        .q_terms
        .as_deref()
        .and_then(|terms| {
            terms
                .iter()
                .filter(|t| t.chars().count() >= 3)
                .max_by_key(|t| t.chars().count())
        })
        .map(|t| format!("%{t}%"));
    let action_like = filter.action_contains.as_deref().map(|q| format!("%{q}%"));
    let resource_like = filter
        .resource_type_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let desc_like = filter
        .description_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let ip_like = filter
        .ip_address_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let name_like = filter
        .identity_name_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let owner_name_like = filter
        .owner_user_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let kinds = filter.identity_kinds.as_deref();
    let tags = filter.tags.as_deref();
    let tag_like = filter.tag_contains.as_deref().map(|q| format!("%{q}%"));
    // No join. `identities` used to be LEFT JOINed twice to reach the actor's
    // name and their owner's; both are columns on the row since migration 110.
    // What remains of the identity lookup — kind and ownership — moved into
    // EXISTS subqueries so it costs nothing when those filters are absent,
    // which is nearly always. The join was not free: on 400k rows it was ~1.7 s
    // of the 2.5 s a no-match search used to take, paid once per candidate row.
    sqlx::query_as!(
        AuditRow,
        "SELECT a.id, a.org_id, a.identity_id, a.action, a.resource_type, a.resource_id, a.detail, a.description, a.ip_address, a.created_at, a.impersonated_by_identity_id, a.tags, a.actor_name, a.owner_user_name
         FROM audit_log a
         WHERE a.org_id = $1
           AND ($2::text IS NULL OR a.action = $2)
           AND ($3::text IS NULL OR a.resource_type = $3)
           AND ($4::uuid IS NULL OR a.identity_id = $4)
           AND ($5::timestamptz IS NULL OR a.created_at >= $5)
           AND ($6::timestamptz IS NULL OR a.created_at <= $6)
           -- Every free-text term must hit at least one of the three columns.
           -- Phrased as no-term-fails so one NOT EXISTS covers N terms.
           -- COALESCE is load-bearing: `description` and `actor_name` are
           -- nullable, and an unmatched NULL makes the OR NULL, which the
           -- surrounding NOT would turn back into a pass.
           AND ($7::text[] IS NULL
                OR NOT EXISTS (
                    SELECT 1 FROM unnest($7::text[]) AS term
                    WHERE NOT COALESCE(a.action ILIKE term
                                    OR a.description ILIKE term
                                    OR a.actor_name ILIKE term, FALSE)))
           -- Redundant by construction, indexable unlike the clause above.
           -- Must spell the expression exactly as idx_audit_log_search_trgm
           -- does, or the index is not considered.
           AND ($25::text IS NULL
                OR (a.action || ' ' || COALESCE(a.description, '') || ' ' || COALESCE(a.actor_name, '')) ILIKE $25)
           AND ($8::uuid IS NULL OR a.id = $8)
           AND ($9::uuid IS NULL
                OR a.id = $9
                OR a.identity_id = $9
                OR a.resource_id = $9
                OR CASE WHEN a.detail->>'execution_id' ~ '^[0-9a-fA-F-]{36}$'
                        THEN (a.detail->>'execution_id')::uuid = $9
                        ELSE FALSE END
                OR CASE WHEN a.detail->>'replayed_from_approval' ~ '^[0-9a-fA-F-]{36}$'
                        THEN (a.detail->>'replayed_from_approval')::uuid = $9
                        ELSE FALSE END)
           AND ($12::text IS NULL OR a.action ILIKE $12)
           AND ($13::text IS NULL OR a.resource_type ILIKE $13)
           AND ($14::text IS NULL OR a.description = $14)
           AND ($15::text IS NULL OR a.description ILIKE $15)
           AND ($16::text IS NULL OR a.ip_address = $16)
           AND ($17::text IS NULL OR a.ip_address ILIKE $17)
           AND ($18::text IS NULL OR a.actor_name ILIKE $18)
           -- Kind and ownership are the only things still worth a lookup, and
           -- an EXISTS keeps the planner from paying for one when they are
           -- absent. Semantics match the LEFT JOIN they replace: a row whose
           -- identity is gone matches neither.
           AND ($19::text[] IS NULL
                OR EXISTS (SELECT 1 FROM identities i
                            WHERE i.id = a.identity_id AND i.org_id = a.org_id
                              AND i.kind = ANY($19)))
           AND ($20::uuid IS NULL
                OR a.identity_id = $20
                OR EXISTS (SELECT 1 FROM identities i
                            WHERE i.id = a.identity_id AND i.org_id = a.org_id
                              AND i.owner_id = $20))
           AND ($21::text IS NULL OR a.owner_user_name ILIKE $21)
           AND ($22::boolean IS NULL
                OR ($22 AND a.detail->>'is_error' = 'true')
                OR (NOT $22 AND a.detail->>'is_error' = 'false'))
           -- Containment (not overlap): every requested tag must be present.
           AND ($23::text[] IS NULL OR a.tags @> $23)
           -- No index for this one; it rides the org/created_at scan alongside
           -- the other ILIKE filters.
           AND ($24::text IS NULL
                OR EXISTS (SELECT 1 FROM unnest(a.tags) t WHERE t ILIKE $24))
           -- Keyset cursor, in two conjuncts on purpose. The first is a plain
           -- range bound idx_audit_log_org_created_id serves as a starting
           -- point; a row-comparison `(created_at, id) < ($26, $27)` is not
           -- reliably extracted as an index qual. The second drops the rows
           -- already seen at the boundary timestamp.
           --
           -- The `IS NOT NULL` on $27 is load-bearing rather than defensive.
           -- The first conjunct is deliberately inclusive (`<=`) so the second
           -- can resolve the tie, which means a `before` supplied *without* a
           -- `before_id` must fall back to a strict bound here — otherwise the
           -- boundary row is admitted by the first conjunct and never removed,
           -- and every page repeats the previous page's last row. When enough
           -- rows share that timestamp to fill a page, it never advances at
           -- all. `until` is the inclusive filter; `before` is a cursor.
           AND ($26::timestamptz IS NULL OR a.created_at <= $26)
           AND ($26::timestamptz IS NULL
                OR a.created_at < $26
                OR ($27::uuid IS NOT NULL AND a.id < $27))
         ORDER BY a.created_at DESC, a.id DESC
         LIMIT $10 OFFSET $11",
        filter.org_id,
        filter.action,
        filter.resource_type,
        filter.identity_id,
        filter.since,
        filter.until,
        q_likes.as_deref(),
        filter.event_id,
        filter.uuid,
        filter.limit,
        filter.offset,
        action_like,
        resource_like,
        filter.description,
        desc_like,
        filter.ip_address,
        ip_like,
        name_like,
        kinds,
        filter.owner_user_id,
        owner_name_like,
        filter.is_error,
        tags,
        tag_like,
        q_prune,
        filter.before,
        filter.before_id,
    )
    .fetch_all(pool)
    .await
}
