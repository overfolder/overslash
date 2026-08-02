/**
 * Error model.
 *
 * The gateway's auth-recovery envelopes are the load-bearing contract for "your
 * agent needs the user to reconnect something", and every integrator that has
 * gone without an SDK has re-implemented lifting them (Overfolder does it in
 * ~120 lines of Rust). They lift here, once.
 *
 * Mirrors the `IntoResponse` bodies in `crates/overslash-api/src/error.rs`.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown, message?: string) {
    super(message ?? `Overslash API error ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }

  /** The `error` discriminator, when the body carries one. */
  get code(): string | undefined {
    return readString(this.body, 'error');
  }
}

export type AuthActionKind =
  | 'needs_authentication'
  | 'reauth_required'
  | 'missing_scopes';

/**
 * A typed auth-recovery envelope.
 *
 * `headless` is not an edge case to swallow — it is the white-label contract
 * (D21). A headless org mints no gated URL because its end users have no
 * Overslash session; the integration runs its own OAuth dance and re-imports.
 * So `authUrl` is absent exactly when `headless` is true, and a caller that
 * opens `authUrl` without checking will open `undefined`.
 */
export class AuthActionError extends ApiError {
  readonly kind: AuthActionKind;
  readonly headless: boolean;
  readonly provider?: string;
  readonly connectionId?: string;
  readonly serviceInstanceId?: string;
  readonly service?: string;
  readonly accountEmail?: string;
  /** Absent for headless orgs. */
  readonly authUrl?: string;
  /** Shortened form of `authUrl`, when the shortener is configured. */
  readonly short?: string;
  /** `missing_scopes` only: the Overslash-owned scope-upgrade endpoint. */
  readonly upgradeUrl?: string;
  /**
   * The full scope set the action requires.
   *
   * The two envelopes name this field differently on the wire —
   * `needs_authentication` sends `required_scopes`, `missing_scopes` sends
   * `required` — so both are read here. Papering over that inconsistency is
   * exactly the sort of thing every integrator would otherwise rediscover.
   */
  readonly requiredScopes?: string[];
  /** `missing_scopes`: the subset not currently granted — the delta to obtain. */
  readonly missingScopes?: string[];
  /** `reauth_required`: why the stored token stopped working. */
  readonly reason?: string;

  constructor(status: number, body: unknown, kind: AuthActionKind) {
    super(status, body, `Overslash ${kind}`);
    this.name = 'AuthActionError';
    this.kind = kind;
    this.headless = readBoolean(body, 'headless') ?? false;
    this.provider = readString(body, 'provider');
    this.connectionId = readString(body, 'connection_id');
    this.serviceInstanceId = readString(body, 'service_instance_id');
    this.service = readString(body, 'service');
    this.accountEmail = readString(body, 'account_email');
    this.authUrl = readString(body, 'auth_url');
    this.short = readString(body, 'short');
    this.upgradeUrl = readString(body, 'upgrade_url');
    this.requiredScopes =
      readStringArray(body, 'required_scopes') ?? readStringArray(body, 'required');
    this.missingScopes = readStringArray(body, 'missing');
    this.reason = readString(body, 'reason');
  }
}

/** The browser refused to open the OAuth popup. Surfaced as state, not thrown. */
export class PopupBlockedError extends Error {
  constructor(message = 'The browser blocked the authorization popup') {
    super(message);
    this.name = 'PopupBlockedError';
  }
}

/** `waitForApproval` gave up before the approval settled. */
export class WaitTimeoutError extends Error {
  readonly approvalId: string;
  constructor(approvalId: string, timeoutMs: number) {
    super(`Approval ${approvalId} did not settle within ${timeoutMs}ms`);
    this.name = 'WaitTimeoutError';
    this.approvalId = approvalId;
  }
}

/** The server speaks a stream protocol version this SDK does not understand. */
export class StreamVersionError extends Error {
  readonly serverVersion: number;
  readonly supportedVersion: number;
  constructor(serverVersion: number, supportedVersion: number) {
    super(
      `Event stream protocol v${serverVersion} is newer than the v${supportedVersion} this SDK understands`,
    );
    this.name = 'StreamVersionError';
    this.serverVersion = serverVersion;
    this.supportedVersion = supportedVersion;
  }
}

const AUTH_ACTION_CODES: Record<string, AuthActionKind> = {
  needs_authentication: 'needs_authentication',
  reauth_required: 'reauth_required',
  missing_scopes: 'missing_scopes',
};

/**
 * Build the right error for a failed response. Auth-recovery envelopes become
 * `AuthActionError`; everything else stays an `ApiError`.
 */
export function toApiError(status: number, body: unknown): ApiError {
  const code = readString(body, 'error');
  const kind = code ? AUTH_ACTION_CODES[code] : undefined;
  if (kind) return new AuthActionError(status, body, kind);
  return new ApiError(status, body);
}

/**
 * Pull the human-readable reason out of an error.
 *
 * The gateway's simple errors serialise as `{ "error": "<message>" }`, so this
 * surfaces the server's own words ("admin access required") rather than a bare
 * status code. Ported from `dashboard/src/lib/approvals/format.ts`.
 */
export function pickApiError(e: unknown, fallback = 'Something went wrong'): string {
  if (e instanceof ApiError) {
    const reason = readString(e.body, 'error') ?? readString(e.body, 'message');
    if (reason) return reason;
    if (typeof e.body === 'string' && e.body.trim()) return e.body;
    return `${fallback} (${e.status})`;
  }
  if (e instanceof Error && e.message) return e.message;
  return fallback;
}

function readString(body: unknown, key: string): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const v = (body as Record<string, unknown>)[key];
  return typeof v === 'string' ? v : undefined;
}

function readBoolean(body: unknown, key: string): boolean | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const v = (body as Record<string, unknown>)[key];
  return typeof v === 'boolean' ? v : undefined;
}

function readStringArray(body: unknown, key: string): string[] | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const v = (body as Record<string, unknown>)[key];
  if (!Array.isArray(v)) return undefined;
  return v.filter((x): x is string => typeof x === 'string');
}
