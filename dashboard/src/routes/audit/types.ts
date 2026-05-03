/** Mirrors crates/overslash-api/src/routes/audit.rs AuditEntry */
export interface AuditEntry {
	id: string;
	identity_id: string | null;
	identity_name: string | null;
	/** SPIFFE-style hierarchical path of the actor identity, e.g.
	 * `spiffe://acme/user/alice/agent/henry`. Null when the chain could not be
	 * resolved (deleted identity / missing org). Render with IdentityPath. */
	identity_path: string | null;
	/** UUIDs aligned with each `(kind, name)` unit in `identity_path`. Empty
	 * when the path is null. */
	identity_path_ids: string[];
	action: string;
	description: string | null;
	resource_type: string | null;
	resource_id: string | null;
	detail: Record<string, unknown>;
	ip_address: string | null;
	created_at: string;
	impersonated_by_identity_id: string | null;
	impersonated_by_name: string | null;
	/** SPIFFE-style path for the impersonator (when `X-Overslash-As` was used). */
	impersonated_by_path: string | null;
	impersonated_by_path_ids: string[];
}

export interface AuditFilters {
	identity_id?: string;
	action?: string;
	resource_type?: string;
	since?: string;
	until?: string;
	q?: string;
	/** Single-event lookup. Powers the `?event=<uuid>` deep-link confirmation
	 * fetch — used to pull the targeted event so we can render an anchor row
	 * even when the user's other filters wouldn't surface it. */
	event_id?: string;
	/** Match a UUID across `id`, `identity_id`, `resource_id`, and the JSONB
	 * `detail` keys `execution_id` / `replayed_from_approval`. */
	uuid?: string;
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
	if (filters.event_id) p.set('event_id', filters.event_id);
	if (filters.uuid) p.set('uuid', filters.uuid);
	return p.toString();
}

export function filtersFromSearchParams(params: URLSearchParams): AuditFilters {
	const f: AuditFilters = {};
	const keys = ['identity_id', 'action', 'resource_type', 'since', 'until', 'q', 'uuid'] as const;
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
