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

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const load: PageLoad = async ({ url }) => {
	const filters: AuditFilters = filtersFromSearchParams(url.searchParams);
	// `?event=<uuid>` is a deep-link target, not a stored filter — keep it out
	// of `filters` so it doesn't narrow the visible page, and fetch it
	// separately so we can render an anchor row even when the active filters
	// wouldn't surface that event.
	const rawEvent = url.searchParams.get('event');
	const eventId = rawEvent && UUID_RE.test(rawEvent) ? rawEvent : null;

	// Identities are scoped to the caller's org by the API; we use them for
	// search bar value autocomplete and to translate `identity = name` chips
	// into the precise `identity_id` filter.
	const identitiesPromise = session
		.get<IdentitySummary[]>('/v1/identities')
		.catch(() => [] as IdentitySummary[]);
	const anchorPromise: Promise<AuditEntry | null> = eventId
		? session
				.get<AuditEntry[]>(`/v1/audit?event_id=${eventId}&limit=1`)
				.then((rows) => rows[0] ?? null)
				.catch(() => null)
		: Promise.resolve(null);
	try {
		const [entries, identities, anchor] = await Promise.all([
			session.get<AuditEntry[]>(`/v1/audit?${buildQuery(filters, PAGE_LIMIT, 0)}`),
			identitiesPromise,
			anchorPromise
		]);
		return {
			entries,
			filters,
			identities,
			eventId,
			anchor,
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
			eventId,
			anchor: await anchorPromise,
			error: { status, message }
		};
	}
};
