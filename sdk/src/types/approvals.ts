/**
 * Approval wire types.
 *
 * Hand-written mirrors of the Rust DTOs (D47). Every type names its source so a
 * change on the Rust side can find its dependents with a grep. The dashboard
 * carries an equivalent set in `dashboard/src/lib/session.ts`; the two are kept
 * deliberately field-identical so the dashboard can adopt these later.
 */

/** Mirrors `overslash_core::permissions::DerivedKey`. */
export interface DerivedKey {
  service: string;
  action: string;
  /**
   * Third key segment verbatim, `label=value` included when the action's scope
   * carries a label (`recipient=jane@example.com`).
   */
  arg: string;
  /**
   * The scope label, when `arg` carries one. Absent for a bare arg — keys from
   * unlabelled scopes and rules typed by hand. Not a param name: an email send
   * files `to`/`cc`/`bcc` alike under `recipient`.
   */
  label?: string;
  /** `arg` with any `label=` prefix stripped. */
  value: string;
}

/** Mirrors `overslash_core::permissions::SuggestedTier`. */
export interface SuggestedTier {
  keys: string[];
  description: string;
}

/**
 * One entry from `approvals.disclosed_fields` — a labelled, human-readable
 * slice of the resolved request, extracted via the template's
 * `x-overslash-disclose` jq filters.
 */
export interface DisclosedField {
  label: string;
  /**
   * Filter output, stringified. Null when the filter produced no value or when
   * `error` is set.
   */
  value: string | null;
  /** Per-field error. Siblings still render — errors are isolated per field. */
  error: string | null;
  /** True when the value hit the per-field `max_chars` clamp or the 10 KB ceiling. */
  truncated: boolean;
  /**
   * True when the template marked this entry `primary`. Primaries render as
   * prominent "hero" values in declaration order; the rest form a table.
   * Omitted when false — the backend skips serialising it.
   */
  primary?: boolean;
}

/** Risk class for a gated action. Read → low, Write → med, Delete → high. */
export type Risk = 'low' | 'med' | 'high';

/** How the viewing identity relates to the requester. */
export type ApprovalRelationship = 'self' | 'downstream' | 'not_in_your_chain';

/**
 * `GET /v1/approvals` scope filter.
 *
 * - `mine` — approvals this identity requested (the outbox).
 * - `assigned` — approvals this identity is the current resolver for (the inbox).
 * - `actionable` — resolvable by this identity or any descendant, excluding
 *   self-requested.
 *
 * Omitting the scope lists org-wide, which this SDK never does by default: that
 * endpoint has no ACL gate, and a widget has no business enumerating an org.
 */
export type ApprovalScope = 'mine' | 'assigned' | 'actionable';

export type ApprovalStatus = 'pending' | 'allowed' | 'denied' | 'expired';

/**
 * Mirrors `crates/overslash-api/src/routes/approvals/mod.rs` `ExecutionSummary`.
 */
export interface ExecutionSummary {
  id: string;
  /**
   * `pending | executing | executed | failed | cancelled | expired` —
   * authoritative values come from the `executions.status` column; the API does
   * no translation. Left as `string` so an unknown future state does not
   * become a type error at the boundary.
   */
  status: string;
  result?: unknown;
  error?: string;
  /**
   * `auto` when the resolve handler kicked off the replay because the
   * requesting identity has `auto_call_on_approve` enabled (the default).
   */
  triggered_by?: 'agent' | 'user' | 'auto';
  started_at?: string;
  completed_at?: string;
  expires_at: string;
  created_at: string;
  /** `http | mcp` — disambiguates `http_status_code`. Absent while pending. */
  runtime?: string;
  /** Upstream HTTP status, for HTTP-runtime executions only. */
  http_status_code?: number;
  /**
   * False until the requesting agent fetches `/v1/approvals/{id}/execution` for
   * the first time. Drives "called but output unread" surfaces.
   */
  output_read: boolean;
}

/**
 * Mirrors `crates/overslash-api/src/routes/approvals/mod.rs` `ApprovalResponse`.
 */
export interface ApprovalResponse {
  id: string;
  identity_id: string;
  /** Alias of `identity_id`, named explicitly for clarity in the bubbling model. */
  requesting_identity_id: string;
  /**
   * The identity currently expected to act. Bubbles upward on explicit
   * `bubble_up` or via the per-org auto-bubble timer.
   */
  current_resolver_identity_id: string;
  /**
   * SPIFFE-style path of the requesting identity, e.g.
   * `spiffe://acme/user/alice/agent/henry`. Null when the chain could not be
   * resolved.
   */
  identity_path: string | null;
  /**
   * Identity ids for each `(kind, name)` unit in `identity_path`, same order.
   * Excludes the org slug, so the length matches the path's unit count.
   */
  identity_path_ids: string[];
  action_summary: string;
  /**
   * System-derived metadata tags describing the gated call (`sql:write`,
   * `table:wh/orders`, `service:metabase`). Empty for approvals created before
   * tagging existed.
   */
  tags: string[];
  permission_keys: string[];
  derived_keys: DerivedKey[];
  suggested_tiers: SuggestedTier[];
  /**
   * Pretty-printed `action_detail` JSONB, truncated server-side at 100 KB on a
   * UTF-8 boundary. Null when no detail was stored.
   */
  action_detail: string | null;
  action_detail_truncated: boolean;
  /** Byte length before truncation. 0 when no detail was stored. */
  action_detail_size_bytes: number;
  /**
   * Labelled summary of the resolved request.
   *
   * Omitted from the JSON entirely when the template declared no disclose
   * entries — the Rust field is `skip_serializing_if = "Option::is_none"`, so
   * this is `undefined` on the wire rather than `null`. Optional here for that
   * reason; check falsiness, not `=== null`.
   */
  disclosed_fields?: DisclosedField[] | null;
  status: string;
  token: string;
  expires_at: string;
  created_at: string;
  /**
   * Replay lifecycle state, present once `/resolve allow` created the pending
   * execution row. Absent on denied / bubbled / pre-replay approvals.
   */
  execution?: ExecutionSummary;
  /**
   * Other pending approvals auto-resolved as a side effect of this call.
   * Populated only on the response to `POST /v1/approvals/{id}/call` when an
   * "allow & remember" rule structurally satisfied siblings.
   */
  cascaded_approval_ids?: string[];
  risk: Risk;
  /**
   * Caller↔requester relationship from the *viewing* identity's perspective.
   * Populated on identity-bound reads; omitted on session reads where the
   * relationship has no defined viewer.
   */
  relationship?: ApprovalRelationship;
}

/** Body of `POST /v1/approvals/{id}/resolve`. */
export interface ResolveApprovalRequest {
  resolution: Resolution;
  /**
   * Keys to persist as permission rules. Each must appear verbatim in a
   * `suggested_tiers` entry, or cover one of the approval's `permission_keys`.
   * Rules are only written once the call actually replays.
   */
  remember_keys?: string[];
  /** e.g. `24h`, `7d`, `30d`. Absent means forever. Capped at 365 days. */
  ttl?: string;
}

export type Resolution = 'allow' | 'deny' | 'allow_remember' | 'bubble_up';
