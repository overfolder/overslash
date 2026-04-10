import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

export interface ProvideMetadata {
	id: string;
	secret_name: string;
	identity_label: string;
	requested_by_label: string;
	reason: string | null;
	expires_at: string;
	created_at: string;
}

type LoadResult =
	| { state: 'ready'; req_id: string; token: string; meta: ProvideMetadata }
	| { state: 'expired'; req_id: string }
	| { state: 'already_fulfilled'; req_id: string }
	| { state: 'invalid'; req_id: string }
	| { state: 'missing_token'; req_id: string }
	| { state: 'server_error'; req_id: string };

function mapError(status: number, body: { error?: string } | null): LoadResult['state'] {
	const code = body?.error ?? '';
	if (status === 410 && code.includes('already_fulfilled')) return 'already_fulfilled';
	if (status === 410) return 'expired';
	if (status === 400) return 'invalid';
	if (status >= 500) return 'server_error';
	return 'invalid';
}

export const load: PageLoad = async ({ params, url, fetch }): Promise<LoadResult> => {
	const req_id = params.req_id;
	const token = url.searchParams.get('token');
	if (!token) return { state: 'missing_token', req_id };

	// Plain fetch — must NOT send credentials. This page is unauthenticated.
	const r = await fetch(
		`/public/secrets/provide/${encodeURIComponent(req_id)}?token=${encodeURIComponent(token)}`,
		{ method: 'GET', credentials: 'omit' }
	);
	if (!r.ok) {
		const body = await r.json().catch(() => null);
		return { state: mapError(r.status, body), req_id } as LoadResult;
	}
	const meta: ProvideMetadata = await r.json();
	return { state: 'ready', req_id, token, meta };
};
