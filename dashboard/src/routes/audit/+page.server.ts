import type { PageServerLoad } from './$types';
import type { AuditFilters, EventCategory } from '$lib/types';
import { EVENT_CATEGORY_MAP } from '$lib/types';
import { fetchAuditLogs, fetchIdentities, fetchServices } from '$lib/server/api';

const PAGE_SIZE = 20;

export const load: PageServerLoad = async ({ url }) => {
	const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1'));
	const identityId = url.searchParams.get('identity') || undefined;
	const category = (url.searchParams.get('category') as EventCategory) || undefined;
	const service = url.searchParams.get('service') || undefined;
	const since = url.searchParams.get('since') || undefined;
	const until = url.searchParams.get('until') || undefined;

	if (category && !EVENT_CATEGORY_MAP[category]) {
		// Invalid category, ignore it
	}

	function toISOSafe(val: string | undefined): string | undefined {
		if (!val) return undefined;
		const d = new Date(val);
		return isNaN(d.getTime()) ? undefined : d.toISOString();
	}

	const filters: AuditFilters = {
		identity_id: identityId,
		category: category && EVENT_CATEGORY_MAP[category] ? category : undefined,
		service,
		since: toISOSafe(since),
		until: toISOSafe(until),
		page,
		limit: PAGE_SIZE
	};

	const [entries, identities, services] = await Promise.all([
		fetchAuditLogs(filters),
		fetchIdentities(),
		fetchServices()
	]);

	const hasNextPage = entries.length > PAGE_SIZE;
	const displayEntries = hasNextPage ? entries.slice(0, PAGE_SIZE) : entries;

	const identityMap: Record<string, { name: string; kind: string }> = {};
	for (const identity of identities) {
		identityMap[identity.id] = { name: identity.name, kind: identity.kind };
	}

	return {
		entries: displayEntries,
		identities,
		services,
		identityMap,
		page,
		hasNextPage,
		filters: {
			identity: identityId ?? '',
			category: filters.category ?? '',
			service: service ?? '',
			since: since ?? '',
			until: until ?? ''
		}
	};
};
