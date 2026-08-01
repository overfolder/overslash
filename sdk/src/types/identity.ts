/**
 * Identity and service wire types.
 *
 * Mirrors `crates/overslash-api/src/routes/identities/crud.rs` (`whoami`) and
 * the service listing in `routes/services/`.
 */

export type IdentityKind = 'user' | 'agent' | 'sub_agent';

/**
 * `GET /v1/whoami` — the bearer-usable self-introspection probe. Unlike
 * `/auth/me*`, it does not require a session cookie, which makes it the
 * SDK's connectivity and credential check.
 */
export interface WhoamiResponse {
  org_id: string;
  identity_id: string;
  kind: IdentityKind;
  name: string;
  parent_id: string | null;
  owner_id: string | null;
}

/** A service instance as listed by `GET /v1/services`. */
export interface ServiceSummary {
  id: string;
  name: string;
  template_key: string | null;
  status: string;
  description?: string | null;
}
