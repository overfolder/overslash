/**
 * Cookie-session API helpers for the identity hierarchy view.
 *
 * Backed by `session` (HttpOnly cookie auth) — see lib/session.ts.
 */
import { session, type ApprovalResponse } from './session';
import type { Identity, PermissionRule } from './types';

// ─── Identities ───────────────────────────────────────────────────────────

// The Agents view filters archived nodes client-side (so the "Show archived"
// toggle reveals them without a refetch), so we always fetch the full set.
export function listIdentities(): Promise<Identity[]> {
	return session.get<Identity[]>('/v1/identities?include_archived=true');
}

export function getIdentityChain(id: string): Promise<Identity[]> {
	return session.get<Identity[]>(`/v1/identities/${id}/chain`);
}

export interface CreateIdentityRequest {
	name: string;
	kind: 'user' | 'agent' | 'sub_agent';
	parent_id?: string;
	external_id?: string;
	/** Optional. Only meaningful for `agent`/`sub_agent` — server ignores
	 *  it for `user`. Set in the same request so the new row lands in its
	 *  final state without a follow-up PATCH. */
	inherit_permissions?: boolean;
}

export function createIdentity(req: CreateIdentityRequest): Promise<Identity> {
	return session.post<Identity>('/v1/identities', req);
}

export interface UpdateIdentityRequest {
	name?: string;
	parent_id?: string;
	inherit_permissions?: boolean;
}

export function updateIdentity(id: string, req: UpdateIdentityRequest): Promise<Identity> {
	// session helper has no PATCH; do it manually via fetch.
	return fetch(`/v1/identities/${id}`, {
		method: 'PATCH',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(req)
	}).then(async (res) => {
		const text = await res.text();
		if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
		return JSON.parse(text);
	});
}

export function deleteIdentity(id: string): Promise<void> {
	return session.delete<void>(`/v1/identities/${id}`);
}

// ─── Permissions ──────────────────────────────────────────────────────────

export function listPermissions(identity_id: string): Promise<PermissionRule[]> {
	return session.get<PermissionRule[]>(
		`/v1/permissions?identity_id=${encodeURIComponent(identity_id)}`
	);
}

export function deletePermission(id: string): Promise<void> {
	return session.delete<void>(`/v1/permissions/${id}`);
}

/**
 * Reset a rule's expiry. `ttl` is a duration string (`'1h'`/`'24h'`/`'7d'`/`'30d'`)
 * — the new expiry is `now + ttl`. Pass `null` (or `'forever'`) to clear the
 * expiry so the rule never expires. Same PATCH-via-fetch shape as
 * `updateIdentity`, since the session helper has no PATCH.
 */
export function updatePermissionExpiry(id: string, ttl: string | null): Promise<PermissionRule> {
	return fetch(`/v1/permissions/${id}`, {
		method: 'PATCH',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ ttl })
	}).then(async (res) => {
		const text = await res.text();
		if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
		return JSON.parse(text);
	});
}

// ─── Approvals ────────────────────────────────────────────────────────────

export function listApprovals(identity_id?: string): Promise<ApprovalResponse[]> {
	const path = identity_id
		? `/v1/approvals?identity_id=${encodeURIComponent(identity_id)}`
		: '/v1/approvals';
	return session.get<ApprovalResponse[]>(path);
}

