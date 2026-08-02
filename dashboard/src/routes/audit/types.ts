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
	/** System-derived metadata tags (`sql:write`, `table:wh/orders`,
	 * `service:metabase`, `outcome:error`, …). Empty for events outside the
	 * action/approval path. Rendered as clickable chips in the detail pane. */
	tags: string[];
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
	/** Comma-separated metadata tags; a row must carry **all** of them. Powers
	 * `tag =`. Same comma convention as `identity_kind`. */
	tag?: string;
	/** Substring against any one tag — finds `table:warehouse/orders` without
	 * knowing the db label. Powers `tag ~`. */
	tag_contains?: string;
	/** Upstream result of execution events (`detail.is_error`). `true` →
	 * executions whose upstream reported failure (MCP `is_error` envelope,
	 * upstream HTTP >= 400); `false` → executions that succeeded. Powers
	 * the `result =` search bar key. */
	is_error?: boolean;
}

/** Execution events that carry the normalized `detail.is_error` flag. */
const EXECUTION_ACTIONS = ['action.executed', 'action.streamed'];

/** Upstream-error presence for execution events. Reads the normalized
 * `detail.is_error` flag; falls back to `detail.status_code` for rows
 * written before the flag was normalized onto HTTP executions. */
export function upstreamError(entry: AuditEntry): boolean {
	if (!EXECUTION_ACTIONS.includes(entry.action)) return false;
	if (entry.detail.is_error === true) return true;
	if (entry.detail.is_error === false) return false;
	const code = entry.detail.status_code;
	return typeof code === 'number' && code >= 400;
}

/** Captured upstream response on execution events (`detail.response`),
 * present when the org's audit response-body mode enabled capture for the
 * row. `skipped` replaces the body fields on streamed executions, whose
 * body never passes through a buffer the gateway could sample. */
export interface AuditResponseCapture {
	body?: string;
	truncated?: boolean;
	content_type?: string;
	skipped?: string;
}

export function responseCapture(entry: AuditEntry): AuditResponseCapture | null {
	const r = entry.detail.response;
	if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
	return r as AuditResponseCapture;
}

/** Secret-safe transport-failure summary (`detail.error`) on execution
 * events whose upstream never produced a response (DNS/connect/timeout,
 * body over the buffering limit, MCP transport errors). */
export interface AuditTransportError {
	kind: string;
	message: string;
}

export function transportError(entry: AuditEntry): AuditTransportError | null {
	const e = entry.detail.error;
	if (!e || typeof e !== 'object' || Array.isArray(e)) return null;
	const { kind, message } = e as Record<string, unknown>;
	if (typeof kind !== 'string' || typeof message !== 'string') return null;
	return { kind, message };
}

/** Human-readable upstream result for the expanded pane, or null for
 * non-execution events. "Upstream error — HTTP 502" / "Upstream error —
 * tool reported error" (MCP) / "Transport error — could not connect to
 * upstream" / "Success — HTTP 200" / "Success". */
export function upstreamResultLabel(entry: AuditEntry): string | null {
	if (!EXECUTION_ACTIONS.includes(entry.action)) return null;
	const failed = upstreamError(entry);
	const code = entry.detail.status_code;
	const isMcp = entry.detail.runtime === 'mcp';
	if (failed) {
		// Transport-failure rows carry `error` and no status_code — the
		// upstream never answered, which is a different story than an
		// HTTP error response.
		const transport = transportError(entry);
		if (transport) return `Transport error — ${transport.message}`;
		if (isMcp) return 'Upstream error — tool reported error';
		return typeof code === 'number' ? `Upstream error — HTTP ${code}` : 'Upstream error';
	}
	// Pre-flag MCP rows without is_error still land here as success — the
	// envelope's 200 carries no signal, so don't render a misleading code.
	if (isMcp) return 'Success';
	return typeof code === 'number' ? `Success — HTTP ${code}` : 'Success';
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
	if (filters.tag) p.set('tag', filters.tag);
	if (filters.tag_contains) p.set('tag_contains', filters.tag_contains);
	if (filters.is_error !== undefined) p.set('is_error', String(filters.is_error));
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
		'owner_user_contains',
		'tag',
		'tag_contains'
	] as const;
	for (const k of keys) {
		const v = params.get(k);
		if (v) f[k] = v;
	}
	// Boolean param: parse explicitly so `is_error=false` survives the
	// round-trip instead of being treated as truthy/absent.
	const isError = params.get('is_error');
	if (isError === 'true') f.is_error = true;
	else if (isError === 'false') f.is_error = false;
	return f;
}

export function filtersToSearchString(filters: AuditFilters): string {
	const p = new URLSearchParams();
	for (const [k, v] of Object.entries(filters)) {
		// `v !== undefined` (not truthiness) so `is_error: false` is kept.
		if (v !== undefined && v !== '') p.set(k, String(v));
	}
	const s = p.toString();
	return s ? `?${s}` : '';
}
