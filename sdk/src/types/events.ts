/**
 * Event wire types — shared by the SSE stream and webhooks.
 *
 * D45 made the two transports byte-identical on purpose ("the same event
 * payload regardless of transport"), so there is deliberately **one** envelope
 * type here rather than one per transport: two would encode a difference that
 * does not exist and would let one drift from the other. A consumer that
 * already verifies webhooks needs no second parser for the stream.
 *
 * Mirrors `crates/overslash-api/src/services/events/types.rs` (`EventType`,
 * `Topic`) and the payloads built in `services/events/approvals.rs`,
 * `routes/approvals/{resolve,replay}.rs`, `routes/connections/`, and
 * `routes/secret_requests.rs`.
 */

/** Subscription topic. Unknown topics are a 400 that names the offender. */
export type Topic = 'approvals' | 'connections' | 'secrets';

export const APPROVAL_EVENT_TYPES = [
  'approval.created',
  /**
   * Derived: fired after creation and again after every hand-up, so a caller
   * that only wants an inbox subscribes to one type instead of reconstructing
   * "is this mine now?" from two shapes.
   */
  'approval.pending',
  'approval.bubbled',
  'approval.resolved',
  'approval.executed',
  'approval.execution_failed',
  'approval.execution_cancelled',
] as const;

export const CONNECTION_EVENT_TYPES = [
  'connection.created',
  'connection.updated',
  'connection.scopes_upgraded',
  'connection.deleted',
] as const;

export const SECRET_EVENT_TYPES = [
  'secret_request.created',
  'secret_request.fulfilled',
] as const;

/** Every event name the server can put on the wire. */
export const WIRE_EVENT_TYPES = [
  ...APPROVAL_EVENT_TYPES,
  ...CONNECTION_EVENT_TYPES,
  ...SECRET_EVENT_TYPES,
] as const;

export type WireEventType = (typeof WIRE_EVENT_TYPES)[number];

/**
 * `stream.resync` is synthesised client-side and never sent by the server. It
 * means "you may have missed events" and is the cue to refetch. The SDK owns
 * its resume cursor, so unlike a raw `EventSource` consumer it only fires when
 * a reconnect happens with no cursor at all.
 */
export type EventType = WireEventType | 'stream.resync';

/**
 * The envelope. On SSE this is the `data:` field verbatim; over webhooks it is
 * the POST body.
 */
export interface EventEnvelope<T = Record<string, unknown>> {
  id: string;
  type: string;
  created_at: string;
  data: T;
}

/** Which topic an event type belongs to. */
export function topicForEvent(type: string): Topic | undefined {
  if (type.startsWith('approval.')) return 'approvals';
  if (type.startsWith('connection.')) return 'connections';
  if (type.startsWith('secret_request.')) return 'secrets';
  return undefined;
}

/**
 * An identity named in `can_be_handled_by` — the current resolver and its
 * strict ancestors, minus the requester, who can never resolve its own request.
 */
export interface EventIdentityRef {
  identity_id: string;
  kind: string;
  name: string;
}

/**
 * Union of the approval payload fields across the seven approval events. Every
 * field is optional because no single event carries all of them, and payloads
 * are routing hints rather than state — refetch the approval rather than
 * rendering from these.
 */
export interface ApprovalEventData {
  approval_id: string;
  identity_id?: string;
  /** `approval.created` — the identity in the chain where the permission gap sits. */
  gap_identity_id?: string;
  /** `approval.created`, `approval.pending`. */
  current_resolver_identity_id?: string;
  /** `approval.created`, `approval.pending`. */
  can_be_handled_by?: EventIdentityRef[];
  action_summary?: string;
  permission_keys?: string[];
  /** `approval.pending` — why it is waiting now: `created` or `bubbled`. */
  reason?: 'created' | 'bubbled';
  /** `approval.bubbled` — the resolver that handed it up. */
  from?: string;
  /** `approval.bubbled` — the resolver that now holds it. */
  to?: string;
  /** `approval.bubbled` — whether a user or the auto-bubble sweep moved it. */
  via?: 'user' | 'auto';
  /** `approval.resolved` — the approval's new status. */
  status?: string;
  /** `approval.resolved` — present once a pending execution row exists. */
  execution?: { id: string; status: string; expires_at: string };
  /** `approval.resolved` from a cascade. */
  resolved_by?: string;
  /** `approval.executed` / `execution_failed` / `execution_cancelled`. */
  execution_id?: string;
  triggered_by?: 'agent' | 'user' | 'auto';
  error?: string | null;
  summary?: unknown;
  /**
   * Present only on `approval.executed` for auto-fired executions, so a
   * white-label platform can render the outcome without a follow-up fetch.
   * Truncated at the same 256 KB cap `ExecutionSummary` uses.
   */
  result?: unknown;
  cascaded_approval_ids?: string[];
}

export interface ConnectionEventData {
  connection_id: string;
  org_id?: string;
  identity_id?: string;
  provider?: string;
  account_email?: string | null;
  scopes?: string[];
  /** True when the connection arrived via `POST /v1/connections/import`. */
  imported?: boolean;
}

/**
 * Secret-request payloads deliberately carry **no** `token`, `url` or
 * `short_url`: that URL is a bearer capability and webhook subscriptions are
 * org-wide, so including it would let any operator who can configure a hook
 * fulfil any secret request in the org.
 */
export interface SecretRequestEventData {
  request_id: string;
  secret_name: string;
  identity_id: string;
  requested_by: string;
  /** `secret_request.created`. */
  expires_at?: string;
  /** `secret_request.fulfilled`. */
  version?: number;
  provisioned_by_user_id?: string | null;
  user_signed?: boolean;
}

/** Payload of the `stream.open` frame: the cursor to resume from, and the protocol version. */
export interface StreamOpenData {
  cursor: number;
  v: number;
}

/** The wire-format version this SDK understands. */
export const SUPPORTED_STREAM_VERSION = 1;
