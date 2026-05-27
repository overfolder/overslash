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
	// Per-column `~` (contains) + `=` (match) filters. `*_contains` are
	// case-insensitive substrings.
	action_contains?: string;
	resource_type_contains?: string;
	description?: string;
	description_contains?: string;
	ip_address?: string;
	ip_address_contains?: string;
	/** Substring on the actor identity name; powers `agent ~` / `user ~` /
	 * `identity ~`, scoped by `identity_kind`. */
	identity_name_contains?: string;
	/** Comma-separated identity kinds (e.g. `user` or `agent,sub_agent`). */
	identity_kind?: string;
	/** Owning user (root of the actor's chain): matches the user acting directly
	 * or any agent they own. Powers `user =` / `user = me`. */
	owner_user_id?: string;
	/** Substring on the owning user's name. Powers `user ~`. */
	owner_user_contains?: string;
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
	if (filters.action_contains) p.set('action_contains', filters.action_contains);
	if (filters.resource_type_contains)
		p.set('resource_type_contains', filters.resource_type_contains);
	if (filters.description) p.set('description', filters.description);
	if (filters.description_contains) p.set('description_contains', filters.description_contains);
	if (filters.ip_address) p.set('ip_address', filters.ip_address);
	if (filters.ip_address_contains) p.set('ip_address_contains', filters.ip_address_contains);
	if (filters.identity_name_contains)
		p.set('identity_name_contains', filters.identity_name_contains);
	if (filters.identity_kind) p.set('identity_kind', filters.identity_kind);
	if (filters.owner_user_id) p.set('owner_user_id', filters.owner_user_id);
	if (filters.owner_user_contains) p.set('owner_user_contains', filters.owner_user_contains);
	return p.toString();
}

export function filtersFromSearchParams(params: URLSearchParams): AuditFilters {
	const f: AuditFilters = {};
	const keys = [
		'identity_id',
		'action',
		'resource_type',
		'since',
		'until',
		'q',
		'uuid',
		'action_contains',
		'resource_type_contains',
		'description',
		'description_contains',
		'ip_address',
		'ip_address_contains',
		'identity_name_contains',
		'identity_kind',
		'owner_user_id',
		'owner_user_contains'
	] as const;
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
