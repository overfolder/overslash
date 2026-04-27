/** Mirrors crates/overslash-api/src/routes/audit.rs AuditEntry */
export interface AuditEntry {
	id: string;
	identity_id: string | null;
	identity_name: string | null;
	action: string;
	description: string | null;
	resource_type: string | null;
	resource_id: string | null;
	detail: Record<string, unknown>;
	ip_address: string | null;
	created_at: string;
	impersonated_by_identity_id: string | null;
	impersonated_by_name: string | null;
}

export interface AuditFilters {
	identity_id?: string;
	action?: string;
	resource_type?: string;
	since?: string;
	until?: string;
	q?: string;
}

export const PAGE_LIMIT = 50;

export function buildQuery(filters: AuditFilters, limit: number, offset: number): string {
	const p = new URLSearchParams();
	p.set('limit', String(limit));
	p.set('offset', String(offset));
	if (filters.identity_id) p.set('identity_id', filters.identity_id);
	if (filters.action) p.set('action', filters.action);
	if (filters.resource_type) p.set('resource_type', filters.resource_type);
	if (filters.since) p.set('since', filters.since);
	if (filters.until) p.set('until', filters.until);
	if (filters.q) p.set('q', filters.q);
	return p.toString();
}

export function filtersFromSearchParams(params: URLSearchParams): AuditFilters {
	const f: AuditFilters = {};
	const keys = ['identity_id', 'action', 'resource_type', 'since', 'until', 'q'] as const;
	for (const k of keys) {
		const v = params.get(k);
		if (v) f[k] = v;
	}
	return f;
}

export function filtersToSearchString(filters: AuditFilters): string {
	const p = new URLSearchParams();
	for (const [k, v] of Object.entries(filters)) {
		if (v) p.set(k, v as string);
	}
	const s = p.toString();
	return s ? `?${s}` : '';
}
