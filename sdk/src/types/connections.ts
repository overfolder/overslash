/**
 * Connection and OAuth-provider wire types.
 *
 * Mirrors `crates/overslash-api/src/routes/connections/`.
 */

/** A service instance bound to a connection, for the "used by" list. */
export interface UsedByService {
  id: string;
  name: string;
  template_key: string;
}

/**
 * What OAuth client credentials a connection uses on its next refresh.
 *
 * Mirrors `services::client_credentials::CredentialSource`, which has exactly
 * these four variants. (The dashboard's copy still carries a fifth,
 * `integration_managed`; that column was dropped in migration 085 and the API
 * no longer emits it.)
 */
export type CredentialSource =
  | { kind: 'byoc' }
  | { kind: 'org_secret' }
  | { kind: 'system' }
  | { kind: 'missing' };

/** Mirrors the `GET /v1/connections` row. */
export interface ConnectionSummary {
  id: string;
  /** Owner identity — the user the linked account belongs to. */
  owner_identity_id: string;
  provider_key: string;
  account_email: string | null;
  scopes: string[];
  used_by_service_templates: string[];
  is_default: boolean;
  /** Preserve this connection when a service bound to it is deleted. */
  keep: boolean;
  /**
   * Must be re-authorised before use (e.g. its pinned BYOC client was
   * replaced). Cleared on the next successful reconnect.
   */
  reauth_required: boolean;
  created_at: string;
}

/** Mirrors `GET /v1/connections/{id}`. */
export interface ConnectionDetail {
  id: string;
  provider_key: string;
  account_email: string | null;
  scopes: string[];
  is_default: boolean;
  keep: boolean;
  reauth_required: boolean;
  created_at: string;
  /** Advances on an in-place reconnect. */
  updated_at: string;
  used_by: UsedByService[];
  credential_source: CredentialSource;
}

/**
 * Body of `POST /v1/connections`. Mirrors
 * `routes/connections/initiate.rs::InitiateConnectionRequest`.
 */
export interface InitiateConnectionRequest {
  provider: string;
  scopes?: string[];
  /**
   * Pin a specific BYOC credential. Omitted, the cascade resolves
   * identity-level → org-level → env fallback.
   */
  byoc_credential_id?: string;
  /**
   * Bind the resulting connection to this user identity rather than the calling
   * agent, so every agent under the user shares it.
   */
  on_behalf_of?: string;
  /** Where the callback redirects once the dance finishes. Allow-listed. */
  return_url?: string;
  /** Service instances to bind atomically when the callback fires. */
  pin_service_ids?: string[];
  /** Singular back-compat alias for `pin_service_ids`. */
  service_instance_id?: string;
}

export interface InitiateConnectionResponse {
  /**
   * Always the Overslash-gated `/connect-authorize?id=…` URL — the raw provider
   * authorize URL is never surfaced.
   */
  auth_url: string;
  short?: string;
  state: string;
  provider: string;
  expires_at: string;
  flow_id: string;
}

export interface UpgradeScopesResponse {
  auth_url: string;
  state: string;
  connection_id: string;
  requested_scopes: string[];
}

/** Entry from `GET /v1/oauth-providers`. */
export interface OAuthProviderInfo {
  key: string;
  display_name: string;
  supports_pkce: boolean;
  has_org_credential: boolean;
  has_system_credential: boolean;
  has_user_byoc_credential: boolean;
  /** Redirect URI the user must register in their own OAuth app. */
  oauth_redirect_uri: string;
  /** JavaScript origin to register alongside the redirect URI. */
  oauth_js_origin: string;
  /**
   * Scopes the backend always merges into any initiate/upgrade flow for this
   * provider so the callback can resolve `account_email`.
   */
  default_identity_scopes: string[];
}
