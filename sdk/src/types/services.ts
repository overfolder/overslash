/**
 * Service-instance wire types.
 *
 * Mirrors `crates/overslash-api/src/routes/services.rs` and
 * `crates/overslash-api/src/routes/actions/probe.rs`.
 */

/**
 * A template's credential probe — the read action a "Test service" button
 * calls. Absent means the template declares no `x-overslash-test`, so there
 * is nothing to offer.
 */
export interface TestActionRef {
  action: string;
  /** The action's one-line summary, for a tooltip. */
  summary?: string;
}

/**
 * The verdict from `POST /v1/services/{id}/test`.
 *
 * Carries no upstream response body on purpose: "do these credentials work"
 * is the whole question, and echoing an arbitrary response through a button
 * anyone with instance access can press would make a disclosure surface out
 * of a diagnostic.
 *
 * `pending_approval` is a real outcome, not an error — the probe runs through
 * the ordinary permission and approval path, so a caller without auto-approval
 * on reads gets an approval instead of a result.
 */
export interface ServiceTestResponse {
  status:
    | 'ok'
    | 'failed'
    | 'denied'
    | 'pending_approval'
    | 'needs_authentication'
    | 'not_supported';
  action?: string;
  /** Upstream HTTP status, when the call reached an upstream. */
  http_status?: number;
  /** Wall time for the whole probe, gateway included. */
  latency_ms?: number;
  /** The call's `action_description` — the line the approval screen shows. */
  summary?: string;
  /** Truncated upstream error text. */
  error?: string;
  approval_url?: string;
  auth_url?: string;
}

/** A service instance's lifecycle status. */
export type ServiceStatus = 'draft' | 'active' | 'archived' | 'pending_setup';

/**
 * The answer from `POST /v1/services/{id}/activate`.
 *
 * Read `status` for whether the service is callable now. Not the verdict: a
 * forced activation carries none at all, and `not_supported` promotes on a
 * verdict that never reached an upstream.
 */
export interface ServiceActivateResponse {
  /** The instance's status *after* the call. */
  status: ServiceStatus;
  /** Absent only when `force` skipped the probe. */
  verdict?: ServiceTestResponse;
}

/**
 * Setup links minted alongside a freshly-created instance, for the credential
 * slots nobody bound.
 *
 * The secret twin of the OAuth `connect` bundle: hand `setup_url` to whoever
 * holds the API key exactly as you would hand over `connect.auth_url`. The
 * value never passes back through the caller.
 */
export interface SetupBundle {
  /** The URL to hand over — the first entry of `requests`. */
  setup_url: string;
  /** Best-effort short form. Absent when the shortener is not configured. */
  short_url?: string;
  /** One entry per unbound slot, each with its own single-use URL. */
  requests: SetupRequestRef[];
  expires_at: string;
}

export interface SetupRequestRef {
  request_id: string;
  /** The template securityScheme slot key this link fills. */
  credential_key: string;
  /** The vault name the value will be stored under. */
  secret_name: string;
  setup_url: string;
  /**
   * Best-effort shortened form of this entry's `setup_url`. Absent when the
   * shortener is unconfigured or the mint failed — `setup_url` always works.
   *
   * Per entry, not just on the bundle: every link is handed to a person
   * separately, so every link wants the form that survives a chat message.
   */
  short_url?: string;
}
