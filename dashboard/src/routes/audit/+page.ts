import { session, ApiError } from '$lib/session';
import type { PageLoad } from './$types';
import {
	buildQuery,
	filtersFromSearchParams,
	PAGE_LIMIT,
	type AuditEntry,
	type AuditFilters
} from './types';

export const ssr = false;
export const prerender = false;

interface IdentitySummary {
	id: string;
	name: string;
}

export const load: PageLoad = async ({ url }) => {
	const filters: AuditFilters = filtersFromSearchParams(url.searchParams);
	// Identities are scoped to the caller's org by the API; we use them for
	// search bar value autocomplete and to translate `identity = name` chips
	// into the precise `identity_id` filter.
	const identitiesPromise = session
		.get<IdentitySummary[]>('/v1/identities')
		.catch(() => [] as IdentitySummary[]);
	try {
		const [entries, identities] = await Promise.all([
			session.get<AuditEntry[]>(`/v1/audit?${buildQuery(filters, PAGE_LIMIT, 0)}`),
			identitiesPromise
		]);
		return {
			entries,
			filters,
			identities,
			error: null as null | { status: number; message: string }
		};
	} catch (e) {
		const status = e instanceof ApiError ? e.status : 0;
		const message =
			e instanceof ApiError ? `Failed to load audit log (${e.status}).` : 'Network error loading audit log.';
		return {
			entries: [] as AuditEntry[],
			filters,
			identities: await identitiesPromise,
			error: { status, message }
		};
	}
};
