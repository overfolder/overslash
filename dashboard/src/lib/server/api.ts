import { env } from '$env/dynamic/private';
import type { AuditEntry, AuditFilters, Identity, ServiceSummary } from '$lib/types';
import { EVENT_CATEGORY_MAP } from '$lib/types';
import { MOCK_IDENTITIES, MOCK_SERVICES, MOCK_AUDIT_ENTRIES } from './mock-data';

function useMock(): boolean {
	return env.MOCK_DATA === 'true';
}

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
	const url = new URL(path, env.OVERSLASH_API_URL);
	if (params) {
		for (const [k, v] of Object.entries(params)) {
			if (v) url.searchParams.set(k, v);
		}
	}
	const res = await fetch(url.toString(), {
		headers: { Authorization: `Bearer ${env.OVERSLASH_API_KEY}` }
	});
	if (!res.ok) {
		throw new Error(`API ${res.status}: ${await res.text()}`);
	}
	return res.json();
}

export async function fetchIdentities(): Promise<Identity[]> {
	if (useMock()) return MOCK_IDENTITIES;
	return apiFetch<Identity[]>('/v1/identities');
}

export async function fetchServices(): Promise<ServiceSummary[]> {
	if (useMock()) return MOCK_SERVICES;
	return apiFetch<ServiceSummary[]>('/v1/services');
}

export async function fetchAuditLogs(filters: AuditFilters): Promise<AuditEntry[]> {
	if (useMock()) return fetchMockAuditLogs(filters);

	const actions = filters.category ? EVENT_CATEGORY_MAP[filters.category] : null;

	if (actions && actions.length > 1) {
		// Fetch enough entries from each action type to cover offset + limit + 1
		// after merging. Each sub-query needs at most offset + limit + 1 entries.
		const needed = (filters.page - 1) * filters.limit + filters.limit + 1;
		const results = await Promise.all(
			actions.map((action) =>
				apiFetch<AuditEntry[]>('/v1/audit', {
					action,
					...(filters.identity_id && { identity_id: filters.identity_id }),
					...(filters.service && { resource_type: filters.service }),
					...(filters.since && { since: filters.since }),
					...(filters.until && { until: filters.until }),
					limit: String(needed),
					offset: '0'
				})
			)
		);
		const offset = (filters.page - 1) * filters.limit;
		return results
			.flat()
			.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
			.slice(offset, offset + filters.limit + 1);
	}

	const params: Record<string, string> = {
		limit: String(filters.limit + 1),
		offset: String((filters.page - 1) * filters.limit)
	};
	if (actions && actions.length === 1) params.action = actions[0];
	if (filters.identity_id) params.identity_id = filters.identity_id;
	if (filters.service) params.resource_type = filters.service;
	if (filters.since) params.since = filters.since;
	if (filters.until) params.until = filters.until;

	return apiFetch<AuditEntry[]>('/v1/audit', params);
}

function fetchMockAuditLogs(filters: AuditFilters): AuditEntry[] {
	let entries = [...MOCK_AUDIT_ENTRIES];

	if (filters.category) {
		const actions = EVENT_CATEGORY_MAP[filters.category];
		entries = entries.filter((e) => actions.includes(e.action));
	}
	if (filters.identity_id) {
		entries = entries.filter((e) => e.identity_id === filters.identity_id);
	}
	if (filters.service) {
		entries = entries.filter((e) => e.resource_type === filters.service);
	}
	if (filters.since) {
		const since = new Date(filters.since).getTime();
		entries = entries.filter((e) => new Date(e.created_at).getTime() >= since);
	}
	if (filters.until) {
		const until = new Date(filters.until).getTime();
		entries = entries.filter((e) => new Date(e.created_at).getTime() <= until);
	}

	entries.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

	const offset = (filters.page - 1) * filters.limit;
	return entries.slice(offset, offset + filters.limit + 1);
}
