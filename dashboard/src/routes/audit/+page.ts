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

export const load: PageLoad = async ({ url }) => {
	const filters: AuditFilters = filtersFromSearchParams(url.searchParams);
	try {
		const entries = await session.get<AuditEntry[]>(
			`/v1/audit?${buildQuery(filters, PAGE_LIMIT, 0)}`
		);
		return { entries, filters, error: null as null | { status: number; message: string } };
	} catch (e) {
		const status = e instanceof ApiError ? e.status : 0;
		const message =
			e instanceof ApiError ? `Failed to load audit log (${e.status}).` : 'Network error loading audit log.';
		return { entries: [] as AuditEntry[], filters, error: { status, message } };
	}
};
