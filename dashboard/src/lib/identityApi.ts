/**
 * Cookie-session API helpers for the identity hierarchy view.
 *
 * Backed by `session` (HttpOnly cookie auth) — see lib/session.ts.
 */
import { session, type ApprovalResponse } from './session';
import type {
	Identity,
	PermissionRule,
	EnrollmentToken,
	CreatedEnrollmentToken
} from './types';

// ─── Identities ───────────────────────────────────────────────────────────

export function listIdentities(): Promise<Identity[]> {
	return session.get<Identity[]>('/v1/identities');
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
	const apiBase = import.meta.env.VITE_API_BASE_URL ?? '';
	return fetch(`${apiBase}/v1/identities/${id}`, {
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

// ─── Approvals ────────────────────────────────────────────────────────────

export function listApprovals(identity_id?: string): Promise<ApprovalResponse[]> {
	const path = identity_id
		? `/v1/approvals?identity_id=${encodeURIComponent(identity_id)}`
		: '/v1/approvals';
	return session.get<ApprovalResponse[]>(path);
}

// ─── Enrollment tokens ────────────────────────────────────────────────────

export function createEnrollmentToken(identity_id: string): Promise<CreatedEnrollmentToken> {
	return session.post<CreatedEnrollmentToken>('/v1/enrollment-tokens', { identity_id });
}

export function listEnrollmentTokens(): Promise<EnrollmentToken[]> {
	return session.get<EnrollmentToken[]>('/v1/enrollment-tokens');
}

export function revokeEnrollmentToken(id: string): Promise<void> {
	return session.delete<void>(`/v1/enrollment-tokens/${id}`);
}
