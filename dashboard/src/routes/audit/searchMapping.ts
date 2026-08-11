import type { SearchKey, SearchValue, Term } from '$lib/search/terms';
import type { AuditFilters } from './types';

/** Time presets accepted by the `time` key. */
const TIME_PRESETS: Record<string, number> = {
	last_hour: 60 * 60 * 1000,
	today: 24 * 60 * 60 * 1000,
	'7d': 7 * 24 * 60 * 60 * 1000,
	'30d': 30 * 24 * 60 * 60 * 1000
};

/** Resource types known to the backend (UI_SPEC §Audit Log "event" key). */
const EVENT_VALUES = [
	'action.executed',
	'approval.created',
	'approval.resolved',
	'secret.accessed',
	'connection.changed',
	'identity.created',
	'identity.provisioned',
	'identity.adopted',
	'identity.deleted',
	'permission.changed',
	'org.creator_admin_added',
	'membership.removed'
];

export interface IdentitySummary {
	id: string;
	name: string;
	kind: string;
}

/** Resource types known to the backend, for `resource` key autocomplete. */
const RESOURCE_VALUES = [
	'approval',
	'secret',
	'connection',
	'identity',
	'permission_rule',
	'service',
	'mcp',
	'org_invite',
	'webhook'
];

const AGENT_KINDS = ['agent', 'sub_agent'];

/** Tag namespaces the backend mints, offered as autocomplete seeds. Nobody
 *  recalls a whole tag, but the namespace is enough to start from — and the
 *  detail pane's chips are the other (and primary) way in. */
const TAG_NAMESPACE_HINTS = [
	'sql:read',
	'sql:write',
	'outcome:error',
	'outcome:ok',
	'risk:read',
	'risk:write',
	'risk:delete',
	'transport:http',
	'transport:mcp',
	'transport:platform',
	'transport:stream'
];

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The logged-in user, used to resolve the special `user = me` value. */
export interface CurrentUser {
	id: string;
	name: string;
}

export function buildAuditSearchKeys(
	identities: IdentitySummary[],
	currentUser?: CurrentUser
): SearchKey[] {
	const agentNames = identities.filter((i) => AGENT_KINDS.includes(i.kind)).map((i) => i.name);
	const userNames = identities.filter((i) => i.kind === 'user').map((i) => i.name);
	// `me` is offered first so it surfaces at the top of the value dropdown.
	const userValues = currentUser ? ['me', ...userNames] : userNames;
	return [
		{ name: 'agent', operators: ['=', '~'], values: agentNames, hint: 'agent name' },
		{
			name: 'user',
			operators: ['=', '~'],
			values: userValues,
			hint: currentUser ? 'owning user · me = you' : 'owning user'
		},
		{
			name: 'identity',
			operators: ['=', '~'],
			values: identities.map((i) => i.name),
			hint: 'identity name'
		},
		{ name: 'event', operators: ['=', '~'], values: EVENT_VALUES, hint: 'event type' },
		{
			name: 'result',
			operators: ['='],
			values: ['error', 'success'],
			hint: 'upstream result of executions'
		},
		{ name: 'resource', operators: ['=', '~'], values: RESOURCE_VALUES, hint: 'resource type' },
		{ name: 'description', operators: ['=', '~'], values: [], hint: 'description text' },
		{ name: 'ip', operators: ['=', '~'], values: [], hint: 'IP address' },
		{
			name: 'tag',
			operators: ['=', '~'],
			values: TAG_NAMESPACE_HINTS,
			hint: 'metadata tag · repeat to narrow (AND)'
		},
		{
			name: 'uuid',
			operators: ['='],
			values: [],
			hint: 'event id, execution id, approval id, …'
		},
		{ name: 'time', operators: ['='], values: Object.keys(TIME_PRESETS), hint: 'time range' }
	];
}

/**
 * Convert a SearchBar value into an AuditFilters object the API understands.
 *
 * Mapping rules:
 * - `event = X` / `~ X`     → action / action_contains
 * - `result = error|success`→ is_error=true/false (upstream result of
 *                             execution events, from detail.is_error)
 * - `resource = X` / `~ X`  → resource_type / resource_type_contains
 * - `description = / ~`     → description / description_contains
 * - `ip = / ~`              → ip_address / ip_address_contains
 * - `agent = NAME`          → identity_id of the agent named NAME (kind-scoped)
 * - `agent ~ NAME`          → identity_name_contains + identity_kind=agent,sub_agent
 * - `user = NAME` / `me`    → owner_user_id (the owning-user subtree: the user
 *                             acting directly OR any agent they own)
 * - `user ~ NAME`           → owner_user_contains (substring on owning-user name)
 * - `identity = NAME`       → identity_id=<resolved UUID> (any kind), else q
 * - `identity ~ NAME`       → identity_name_contains (any kind)
 * - `tag = X` (repeatable)  → tag (comma-joined; a row must carry all of them)
 * - `tag ~ X`               → tag_contains (substring against any one tag)
 * - `<key> = <uuid>`        → the id field directly, skipping name resolution
 * - `time = preset`         → since/until window
 * - free text               → folded into q
 *
 * Exact `agent`/`identity` resolve NAME → identity_id (the actor column); `user`
 * resolves NAME → owner_user_id. A literal UUID value is used as-is. The
 * identities list is org-scoped by the API (`GET /v1/identities` enforces
 * `OrgAcl`), so name→id resolution can never leak across tenants.
 */
export function searchToFilters(
	value: SearchValue,
	identities: IdentitySummary[],
	currentUser?: CurrentUser
): AuditFilters {
	const filters: AuditFilters = {};
	const qTerms: string[] = [];
	const tagTerms: string[] = [];
	for (const t of value.terms) {
		if (t.kind === 'text') qTerms.push(t.value);
	}
	// Resolve a name to an identity id, optionally constrained to a set of
	// kinds (so `agent = bot` doesn't match a user also named `bot`).
	const resolveId = (name: string, kinds?: string[]): string | undefined =>
		identities.find(
			(i) => i.name.toLowerCase() === name.toLowerCase() && (!kinds || kinds.includes(i.kind))
		)?.id;
	for (const expr of value.terms) {
		if (expr.kind !== 'filter') continue;
		if (expr.key === 'event') {
			if (expr.op === '~') filters.action_contains = expr.value;
			else filters.action = expr.value;
		} else if (expr.key === 'result') {
			if (expr.value === 'error') filters.is_error = true;
			else if (expr.value === 'success') filters.is_error = false;
		} else if (expr.key === 'resource') {
			if (expr.op === '~') filters.resource_type_contains = expr.value;
			else filters.resource_type = expr.value;
		} else if (expr.key === 'description') {
			if (expr.op === '~') filters.description_contains = expr.value;
			else filters.description = expr.value;
		} else if (expr.key === 'ip') {
			if (expr.op === '~') filters.ip_address_contains = expr.value;
			else filters.ip_address = expr.value;
		} else if (expr.key === 'user') {
			// `user` matches the owning user *subtree*: the user acting directly
			// or any of their agents (backed by identities.owner_id), so it lines
			// up with the audit table's "User" column.
			if (expr.op === '~') {
				filters.owner_user_contains = expr.value;
			} else if (expr.value === 'me' && currentUser) {
				filters.owner_user_id = currentUser.id;
			} else if (UUID_RE.test(expr.value)) {
				filters.owner_user_id = expr.value;
			} else {
				const id = resolveId(expr.value, ['user']);
				if (id) filters.owner_user_id = id;
				else filters.owner_user_contains = expr.value;
			}
		} else if (expr.key === 'agent') {
			// `agent` stays exact-actor (the specific agent that acted).
			if (expr.op === '~') {
				filters.identity_name_contains = expr.value;
				filters.identity_kind = AGENT_KINDS.join(',');
			} else if (UUID_RE.test(expr.value)) {
				filters.identity_id = expr.value;
			} else {
				const id = resolveId(expr.value, AGENT_KINDS);
				if (id) filters.identity_id = id;
				else qTerms.push(expr.value);
			}
		} else if (expr.key === 'identity') {
			if (expr.op === '~') {
				filters.identity_name_contains = expr.value;
			} else if (UUID_RE.test(expr.value)) {
				filters.identity_id = expr.value;
			} else {
				const id = resolveId(expr.value);
				if (id) filters.identity_id = id;
				else qTerms.push(expr.value);
			}
		} else if (expr.key === 'tag') {
			if (expr.op === '~') {
				filters.tag_contains = expr.value;
			} else {
				// Repeated `tag =` narrows (AND); the API takes them as one
				// comma-separated param, matching the `identity_kind` shape.
				tagTerms.push(expr.value);
			}
		} else if (expr.key === 'uuid') {
			filters.uuid = expr.value;
		} else if (expr.key === 'time') {
			const ms = TIME_PRESETS[expr.value];
			if (ms !== undefined) {
				filters.since = new Date(Date.now() - ms).toISOString();
				filters.until = new Date().toISOString();
			}
		}
	}
	// Comma-joined: the API splits `q` on commas and requires *every* term to
	// match, the same convention `tag` and `identity_kind` use. Joining with a
	// space instead would ask for one literal phrase and match nothing.
	if (qTerms.length) filters.q = qTerms.join(',');
	if (tagTerms.length) filters.tag = tagTerms.join(',');
	return filters;
}

/** Inverse mapping for hydrating the SearchBar from URL query state on load. */
export function filtersToSearch(
	filters: AuditFilters,
	identities: IdentitySummary[],
	currentUser?: CurrentUser
): SearchValue {
	const terms: Term[] = [];
	if (filters.action) terms.push({ kind: 'filter', key: 'event', op: '=', value: filters.action });
	if (filters.action_contains)
		terms.push({ kind: 'filter', key: 'event', op: '~', value: filters.action_contains });
	if (filters.is_error !== undefined)
		terms.push({
			kind: 'filter',
			key: 'result',
			op: '=',
			value: filters.is_error ? 'error' : 'success'
		});
	if (filters.resource_type)
		terms.push({ kind: 'filter', key: 'resource', op: '=', value: filters.resource_type });
	if (filters.resource_type_contains)
		terms.push({ kind: 'filter', key: 'resource', op: '~', value: filters.resource_type_contains });
	if (filters.description)
		terms.push({ kind: 'filter', key: 'description', op: '=', value: filters.description });
	if (filters.description_contains)
		terms.push({ kind: 'filter', key: 'description', op: '~', value: filters.description_contains });
	if (filters.ip_address)
		terms.push({ kind: 'filter', key: 'ip', op: '=', value: filters.ip_address });
	if (filters.ip_address_contains)
		terms.push({ kind: 'filter', key: 'ip', op: '~', value: filters.ip_address_contains });
	if (filters.identity_id) {
		const match = identities.find((i) => i.id === filters.identity_id);
		// `identity_id` is an exact-actor filter (from `agent =` or `identity =`).
		// Reverse agents to `agent`; everything else to `identity` — never to
		// `user`, which now means the owning-user subtree (owner_user_id) and
		// would silently broaden an exact-actor filter on the next edit.
		const key = match && AGENT_KINDS.includes(match.kind) ? 'agent' : 'identity';
		terms.push({ kind: 'filter', key, op: '=', value: match?.name ?? filters.identity_id });
	}
	if (filters.identity_name_contains) {
		const kinds = filters.identity_kind?.split(',') ?? [];
		// `user ~` now maps to owner_user_contains, so a kind=user substring here
		// can only be a legacy/identity match — never reverse it to `user`.
		const key = kinds.some((k) => AGENT_KINDS.includes(k)) ? 'agent' : 'identity';
		terms.push({ kind: 'filter', key, op: '~', value: filters.identity_name_contains });
	}
	if (filters.owner_user_id) {
		const value =
			currentUser && filters.owner_user_id === currentUser.id
				? 'me'
				: (identities.find((i) => i.id === filters.owner_user_id)?.name ?? filters.owner_user_id);
		terms.push({ kind: 'filter', key: 'user', op: '=', value });
	}
	if (filters.owner_user_contains) {
		terms.push({ kind: 'filter', key: 'user', op: '~', value: filters.owner_user_contains });
	}
	if (filters.tag) {
		// One expression per tag, so editing or removing one doesn't drop the rest.
		for (const t of filters.tag.split(',').filter(Boolean)) {
			terms.push({ kind: 'filter', key: 'tag', op: '=', value: t });
		}
	}
	if (filters.tag_contains)
		terms.push({ kind: 'filter', key: 'tag', op: '~', value: filters.tag_contains });
	if (filters.uuid) terms.push({ kind: 'filter', key: 'uuid', op: '=', value: filters.uuid });
	// We can't reliably reverse `time` from since/until alone (presets are
	// snapshotted to ISO timestamps); leave it out and let the user re-pick.
	// Text bubbles come back last; `AuditFilters` is an unordered bag, so the
	// original interleaving of a shared URL can't be recovered.
	for (const q of (filters.q ?? '').split(',')) {
		if (q) terms.push({ kind: 'text', value: q });
	}
	return { terms };
}
