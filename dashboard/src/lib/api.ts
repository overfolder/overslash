import type { Identity, Org, ApiKey, CreatedApiKey, Session } from './types';

const API_BASE = import.meta.env.VITE_API_URL || '';

class ApiError extends Error {
	constructor(
		public status: number,
		message: string
	) {
		super(message);
		this.name = 'ApiError';
	}
}

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
	const res = await fetch(`${API_BASE}${path}`, {
		...options,
		credentials: 'include',
		headers: {
			'Content-Type': 'application/json',
			...options.headers
		}
	});

	if (!res.ok) {
		const body = await res.json().catch(() => ({ error: res.statusText }));
		throw new ApiError(res.status, body.error || res.statusText);
	}

	if (res.status === 204) return undefined as T;
	return res.json();
}

export function getMe(): Promise<Session> {
	return apiFetch('/auth/me');
}

export function getOrg(): Promise<Org> {
	return apiFetch('/v1/orgs/current');
}

export function getIdentities(): Promise<Identity[]> {
	return apiFetch('/v1/identities');
}

export function createIdentity(data: {
	name: string;
	kind: string;
	parent_id?: string | null;
}): Promise<Identity> {
	return apiFetch('/v1/identities', {
		method: 'POST',
		body: JSON.stringify(data)
	});
}

export function updateIdentity(id: string, data: { name: string }): Promise<Identity> {
	return apiFetch(`/v1/identities/${id}`, {
		method: 'PUT',
		body: JSON.stringify(data)
	});
}

export function deleteIdentity(id: string): Promise<void> {
	return apiFetch(`/v1/identities/${id}`, { method: 'DELETE' });
}

export function getApiKeys(identityId?: string): Promise<ApiKey[]> {
	const params = identityId ? `?identity_id=${identityId}` : '';
	return apiFetch(`/v1/api-keys${params}`);
}

export function createApiKey(data: {
	org_id: string;
	identity_id?: string;
	name: string;
}): Promise<CreatedApiKey> {
	return apiFetch('/v1/api-keys', {
		method: 'POST',
		body: JSON.stringify(data)
	});
}

export function revokeApiKey(id: string): Promise<void> {
	return apiFetch(`/v1/api-keys/${id}`, { method: 'DELETE' });
}

export { ApiError };
