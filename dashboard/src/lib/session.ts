/**
 * Cookie-based API client for authenticated dashboard pages.
 *
 * In dev, requests are proxied by Vite to the Rust backend on :3000.
 * Auth relies on the `oss_session` HttpOnly cookie set by the backend.
 */

export class ApiError extends Error {
	constructor(
		public status: number,
		public body: unknown
	) {
		super(`API error ${status}`);
		this.name = 'ApiError';
	}
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const init: RequestInit = {
		method,
		headers: { 'Content-Type': 'application/json' },
		credentials: 'include' // send cookies
	};
	if (body !== undefined) {
		init.body = JSON.stringify(body);
	}

	const res = await fetch(path, init);

	if (!res.ok) {
		let errorBody: unknown;
		try {
			errorBody = await res.json();
		} catch {
			errorBody = await res.text();
		}
		throw new ApiError(res.status, errorBody);
	}

	// Handle 204 No Content
	if (res.status === 204) {
		return undefined as T;
	}

	return res.json();
}

export const session = {
	get: <T>(path: string) => request<T>('GET', path),
	post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
	put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
	patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
	delete: <T>(path: string) => request<T>('DELETE', path)
};

/** Response from GET /auth/me/identity — full identity details */
export interface MeIdentity {
	identity_id: string;
	org_id: string;
	email: string;
	name: string;
	kind: string;
	external_id: string | null;
}
