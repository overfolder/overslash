/**
 * Action-call wire types.
 *
 * Mirrors `crates/overslash-api/src/routes/actions/dto.rs` and the response
 * shapes in `call.rs`.
 */

import type {
  ApprovalRelationship,
  DisclosedField,
  Risk,
  SuggestedTier,
} from './approvals.js';

export interface SecretRef {
  name: string;
  inject_as: 'header' | 'query';
  header_name?: string;
  query_param?: string;
  prefix?: string;
}

export type ResponseFilter = { lang: 'jq'; expr: string };

export type FilterErrorKind =
  | 'body_not_json'
  | 'runtime_error'
  | 'timeout'
  | 'output_overflow';

export type FilteredBody =
  | {
      status: 'ok';
      lang: string;
      values: unknown[];
      original_bytes: number;
      filtered_bytes: number;
    }
  | {
      status: 'error';
      lang: string;
      kind: FilterErrorKind;
      message: string;
      original_bytes: number;
    };

/** Body of `POST /v1/actions/call`. */
export interface CallRequest {
  /** Required. Use `http` for raw HTTP via the synthetic pseudo-service. */
  service: string;
  /**
   * Instance UUID. When set the backend resolves by id (org-scoped) and
   * bypasses the caller-scoped name lookup. Required when an org admin invokes
   * another user's service.
   */
  service_id?: string;
  /** Service + defined action shape: `action` + `params`. */
  action?: string;
  params?: Record<string, unknown>;
  /** Service + HTTP verb shape: `method` + (`path` or `url`). */
  method?: string;
  path?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
  secrets?: SecretRef[];
  prefer_stream?: boolean;
  filter?: ResponseFilter;
  /**
   * Where to send the user after a reactive re-auth flow completes. Subject to
   * the operator's return-URL allow-list.
   */
  return_url?: string;
}

export interface ActionResult {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  duration_ms: number;
  filtered_body?: FilteredBody;
}

/**
 * The `pending_approval` arm, split out because it is the one callers build UI
 * from. It carries the render-form fields of `ApprovalResponse`, so an approval
 * card can be drawn straight from a call result with no second round trip.
 */
export interface PendingApproval {
  status: 'pending_approval';
  approval_id: string;
  approval_url: string;
  action_description: string;
  expires_at: string;
  relationship: ApprovalRelationship;
  suggested_tiers: SuggestedTier[];
  /**
   * Mirrors the requesting identity's `auto_call_on_approve`. When true (the
   * default) allow/allow_remember replays the call automatically. Older builds
   * may omit it — treat `undefined` as true.
   */
  auto_call_on_approve?: boolean;
  disclosed_fields?: DisclosedField[];
  risk: Risk;
  permission_keys: string[];
  /** Redacted, pretty-printed request payload, truncated at 100 KB. */
  action_detail?: string;
  action_detail_truncated: boolean;
  action_detail_size_bytes: number;
}

/**
 * Result of `POST /v1/actions/call`.
 *
 * The SDK always sends `?wrap=true`, which turns the gateway's own auth-401s
 * into `200`s carrying the last two arms. So every *expected* outcome is a
 * value here; only transport failures, 5xx and permission denials throw.
 */
export type CallResponse =
  | {
      status: 'called';
      result: ActionResult;
      action_description: string | null;
      /**
       * True when the upstream itself reported failure (an MCP `is_error`
       * envelope, or an upstream HTTP >= 400) even though the call executed.
       * Optional for wire-compat with older builds.
       */
      is_error?: boolean;
    }
  | PendingApproval
  | { status: 'denied'; reason: string }
  | {
      status: 'needs_authentication';
      service?: string;
      service_instance_id?: string;
      connection_id?: string;
      /** Absent for headless orgs, which run their own OAuth dance (D21). */
      auth_url?: string;
      short?: string;
      raw?: string;
      headless?: boolean;
      provider?: string;
    }
  | {
      status: 'reauth_required';
      connection_id: string;
      auth_url?: string;
      reason: string;
      short?: string;
      raw?: string;
      headless?: boolean;
      provider?: string;
    };
