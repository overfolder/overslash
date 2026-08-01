/**
 * Secret and secret-request wire types.
 *
 * Mirrors `crates/overslash-api/src/routes/secrets.rs` and
 * `crates/overslash-api/src/routes/secret_requests.rs`.
 */

/** `GET /v1/secrets` row, as seen by a user-kind caller. */
export interface SecretSummary {
  name: string;
  current_version: number;
  /**
   * Slot-owner identity. Set on first insert and preserved across versions;
   * null for legacy org-wide rows, which are admin-only.
   */
  owner_identity_id: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * `GET /v1/secrets` row as seen by an agent bearer — deliberately narrower.
 * The agent learns a slot exists and when it last rotated, nothing else.
 */
export interface SecretNameRow {
  name: string;
  version_count: number;
  last_rotated_at: string | null;
}

/** Body of `POST /v1/secrets/requests`. */
export interface CreateSecretRequest {
  secret_name: string;
  /** Identity the secret belongs to. Defaults to the caller's own identity. */
  identity_id?: string;
  reason?: string;
  /** URL lifetime. Clamped to [60, 86400]; defaults to 3600. */
  ttl_seconds?: number;
}

export interface CreateSecretRequestResponse {
  /** `req_<hex>`. */
  id: string;
  /**
   * The bearer capability that lets someone fulfil this request. Anyone holding
   * it can provide the value, so it is deliberately absent from the
   * `secret_request.*` event payloads — do not log or broadcast it.
   */
  token: string;
  url: string;
  /** Best-effort short URL. Absent when the shortener is not configured. */
  short_url?: string;
  expires_at: string;
}

/**
 * Populated when the visitor carried a valid session cookie for the same org.
 * Lets a page render "signed in as …" so they know their identity lands on the
 * audit trail. Cross-tenant sessions are silently ignored.
 */
export interface ViewerInfo {
  identity_id: string;
  email: string;
}

/** `GET /public/secrets/provide/{req_id}?token=…`. */
export interface ProvideMetadata {
  id: string;
  secret_name: string;
  identity_label: string;
  requested_by_label: string;
  reason: string | null;
  expires_at: string;
  created_at: string;
  /**
   * True iff the request was minted while the org had
   * `allow_unsigned_secret_provide = false`. When set, submission is refused
   * without a same-org session — captured at mint time so flipping the org
   * setting cannot retroactively break an in-flight URL.
   */
  require_user_session: boolean;
  viewer: ViewerInfo | null;
}

export interface SubmitProvideResponse {
  ok: boolean;
  name: string;
  version: number;
}

/** Response to `PUT /v1/secrets/{name}`. */
export interface PutSecretResponse {
  name: string;
  version: number;
}
