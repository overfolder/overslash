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
	'permission.changed'
];

export interface IdentitySummary {
	id: string;
	name: string;
}

export function buildAuditSearchKeys(identities: IdentitySummary[]): SearchKey[] {
	return [
		{
			name: 'identity',
			operators: ['=', '~'],
			values: identities.map((i) => i.name),
			hint: 'identity name'
		},
		{ name: 'event', operators: ['='], values: EVENT_VALUES, hint: 'event type' },
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
 * - `event = X`        → action=X (exact match on the action column)
 * - `identity = NAME`  → identity_id=<resolved UUID> when NAME is known in the
 *                        caller's org (precise filter); otherwise falls back to
 *                        q="NAME" (substring across identity name/action/description)
 * - `identity ~ NAME`  → always substring via q
 * - `time = preset`    → since/until window
 * - free text          → folded into q
 *
 * The identities list is org-scoped by the API (`GET /v1/identities` enforces
 * `OrgAcl`), so name→id resolution can never leak across tenants.
 */
export function searchToFilters(value: SearchValue, identities: IdentitySummary[]): AuditFilters {
	const filters: AuditFilters = {};
	const qTerms: string[] = [];
	if (value.freeText) qTerms.push(value.freeText);
	const nameToId = new Map(identities.map((i) => [i.name.toLowerCase(), i.id]));
	for (const expr of value.expressions) {
		if (expr.key === 'event') {
			filters.action = expr.value;
		} else if (expr.key === 'identity') {
			const id = expr.op === '=' ? nameToId.get(expr.value.toLowerCase()) : undefined;
			if (id) {
				filters.identity_id = id;
			} else {
				qTerms.push(expr.value);
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
	if (filters.identity_id) {
		const match = identities.find((i) => i.id === filters.identity_id);
		expressions.push({ key: 'identity', op: '=', value: match?.name ?? filters.identity_id });
	}
	if (filters.uuid) expressions.push({ key: 'uuid', op: '=', value: filters.uuid });
	// We can't reliably reverse `time` from since/until alone (presets are
	// snapshotted to ISO timestamps); leave it out and let the user re-pick.
	return { expressions, freeText: filters.q ?? '' };
}
