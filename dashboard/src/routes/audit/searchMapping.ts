import type { Expression, SearchKey, SearchValue } from '$lib/components/SearchBar.svelte';
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

export function buildAuditSearchKeys(identities: IdentitySummary[]): SearchKey[] {
	const agentNames = identities.filter((i) => AGENT_KINDS.includes(i.kind)).map((i) => i.name);
	const userNames = identities.filter((i) => i.kind === 'user').map((i) => i.name);
	return [
		{ name: 'agent', operators: ['=', '~'], values: agentNames, hint: 'agent name' },
		{ name: 'user', operators: ['=', '~'], values: userNames, hint: 'user name' },
		{
			name: 'identity',
			operators: ['=', '~'],
			values: identities.map((i) => i.name),
			hint: 'identity name'
		},
		{ name: 'event', operators: ['=', '~'], values: EVENT_VALUES, hint: 'event type' },
		{ name: 'resource', operators: ['=', '~'], values: RESOURCE_VALUES, hint: 'resource type' },
		{ name: 'description', operators: ['=', '~'], values: [], hint: 'description text' },
		{ name: 'ip', operators: ['=', '~'], values: [], hint: 'IP address' },
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
 * - `resource = X` / `~ X`  → resource_type / resource_type_contains
 * - `description = / ~`     → description / description_contains
 * - `ip = / ~`              → ip_address / ip_address_contains
 * - `agent = NAME`          → identity_id of the agent named NAME (kind-scoped)
 * - `user = NAME`           → identity_id of the user named NAME
 * - `agent ~` / `user ~`    → identity_name_contains + identity_kind (kind scope)
 * - `identity = NAME`       → identity_id=<resolved UUID> (any kind), else q
 * - `identity ~ NAME`       → identity_name_contains (any kind)
 * - `time = preset`         → since/until window
 * - free text               → folded into q
 *
 * Exact `agent`/`user`/`identity` match resolves NAME → identity_id (the actor
 * column). The identities list is org-scoped by the API (`GET /v1/identities`
 * enforces `OrgAcl`), so name→id resolution can never leak across tenants.
 */
export function searchToFilters(value: SearchValue, identities: IdentitySummary[]): AuditFilters {
	const filters: AuditFilters = {};
	const qTerms: string[] = [];
	if (value.freeText) qTerms.push(value.freeText);
	// Resolve a name to an identity id, optionally constrained to a set of
	// kinds (so `agent = bot` doesn't match a user also named `bot`).
	const resolveId = (name: string, kinds?: string[]): string | undefined =>
		identities.find(
			(i) => i.name.toLowerCase() === name.toLowerCase() && (!kinds || kinds.includes(i.kind))
		)?.id;
	for (const expr of value.expressions) {
		if (expr.key === 'event') {
			if (expr.op === '~') filters.action_contains = expr.value;
			else filters.action = expr.value;
		} else if (expr.key === 'resource') {
			if (expr.op === '~') filters.resource_type_contains = expr.value;
			else filters.resource_type = expr.value;
		} else if (expr.key === 'description') {
			if (expr.op === '~') filters.description_contains = expr.value;
			else filters.description = expr.value;
		} else if (expr.key === 'ip') {
			if (expr.op === '~') filters.ip_address_contains = expr.value;
			else filters.ip_address = expr.value;
		} else if (expr.key === 'agent' || expr.key === 'user') {
			const kinds = expr.key === 'agent' ? AGENT_KINDS : ['user'];
			if (expr.op === '=') {
				const id = resolveId(expr.value, kinds);
				if (id) filters.identity_id = id;
				else qTerms.push(expr.value);
			} else {
				filters.identity_name_contains = expr.value;
				filters.identity_kind = kinds.join(',');
			}
		} else if (expr.key === 'identity') {
			if (expr.op === '=') {
				const id = resolveId(expr.value);
				if (id) filters.identity_id = id;
				else qTerms.push(expr.value);
			} else {
				filters.identity_name_contains = expr.value;
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
	if (qTerms.length) filters.q = qTerms.join(' ');
	return filters;
}

/** Inverse mapping for hydrating the SearchBar from URL query state on load. */
export function filtersToSearch(filters: AuditFilters, identities: IdentitySummary[]): SearchValue {
	const expressions: Expression[] = [];
	if (filters.action) expressions.push({ key: 'event', op: '=', value: filters.action });
	if (filters.action_contains)
		expressions.push({ key: 'event', op: '~', value: filters.action_contains });
	if (filters.resource_type)
		expressions.push({ key: 'resource', op: '=', value: filters.resource_type });
	if (filters.resource_type_contains)
		expressions.push({ key: 'resource', op: '~', value: filters.resource_type_contains });
	if (filters.description)
		expressions.push({ key: 'description', op: '=', value: filters.description });
	if (filters.description_contains)
		expressions.push({ key: 'description', op: '~', value: filters.description_contains });
	if (filters.ip_address) expressions.push({ key: 'ip', op: '=', value: filters.ip_address });
	if (filters.ip_address_contains)
		expressions.push({ key: 'ip', op: '~', value: filters.ip_address_contains });
	if (filters.identity_id) {
		const match = identities.find((i) => i.id === filters.identity_id);
		// Reverse to the most specific key we can given the identity's kind.
		const key = !match ? 'identity' : AGENT_KINDS.includes(match.kind) ? 'agent' : 'user';
		expressions.push({ key, op: '=', value: match?.name ?? filters.identity_id });
	}
	if (filters.identity_name_contains) {
		const kinds = filters.identity_kind?.split(',') ?? [];
		const key = kinds.includes('user')
			? 'user'
			: kinds.some((k) => AGENT_KINDS.includes(k))
				? 'agent'
				: 'identity';
		expressions.push({ key, op: '~', value: filters.identity_name_contains });
	}
	if (filters.uuid) expressions.push({ key: 'uuid', op: '=', value: filters.uuid });
	// We can't reliably reverse `time` from since/until alone (presets are
	// snapshotted to ISO timestamps); leave it out and let the user re-pick.
	return { expressions, freeText: filters.q ?? '' };
}
