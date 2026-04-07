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

export const AUDIT_SEARCH_KEYS: SearchKey[] = [
	{ name: 'identity', operators: ['=', '~'], hint: 'identity name or path' },
	{ name: 'event', operators: ['='], values: EVENT_VALUES, hint: 'event type' },
	{ name: 'time', operators: ['='], values: Object.keys(TIME_PRESETS), hint: 'time range' }
];

/**
 * Convert a SearchBar value into an AuditFilters object the API understands.
 *
 * Mapping rules:
 * - `event = X`        → action=X (exact match on the action column)
 * - `identity = X`     → q="X"   (substring search across identity name/action/description)
 * - `identity ~ X`     → q="X"   (`~` is already substring; same as `=` server-side)
 * - `time = preset`    → since/until window
 * - free text          → folded into q (joined with identity terms by space)
 */
export function searchToFilters(value: SearchValue): AuditFilters {
	const filters: AuditFilters = {};
	const qTerms: string[] = [];
	if (value.freeText) qTerms.push(value.freeText);
	for (const expr of value.expressions) {
		if (expr.key === 'event') {
			filters.action = expr.value;
		} else if (expr.key === 'identity') {
			qTerms.push(expr.value);
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
export function filtersToSearch(filters: AuditFilters): SearchValue {
	const expressions: Expression[] = [];
	if (filters.action) expressions.push({ key: 'event', op: '=', value: filters.action });
	// We can't reliably reverse `time` from since/until alone (presets are
	// snapshotted to ISO timestamps); leave it out and let the user re-pick.
	return { expressions, freeText: filters.q ?? '' };
}
