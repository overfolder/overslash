// Pure-logic checks for the audit search bar ⇄ API filter mapping — no browser,
// no stack.
//
// These two functions are the whole contract behind a shareable /audit URL: the
// bar's bubbles go out as query params and have to come back as the same
// bubbles. Multiple text bubbles are the subtle part — they are comma-joined
// into `q` and AND on the server, so a space-join here would quietly ask for one
// literal phrase and match nothing.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import {
	escapeQTerm,
	filtersToSearch,
	searchToFilters,
	splitQTerms,
	type IdentitySummary
} from '../../../src/routes/audit/searchMapping';
import type { SearchValue, Term } from '../../../src/lib/search/terms';

const IDENTITIES: IdentitySummary[] = [
	{ id: '11111111-1111-1111-1111-111111111111', name: 'ada', kind: 'user' },
	{ id: '22222222-2222-2222-2222-222222222222', name: 'scout', kind: 'agent' }
];
const ME = { id: IDENTITIES[0].id, name: 'ada' };

function value(...terms: Term[]): SearchValue {
	return { terms };
}

test.describe('searchToFilters', () => {
	test('every text bubble goes into q, comma-joined so the API ANDs them', () => {
		const f = searchToFilters(
			value({ kind: 'text', value: 'timeout' }, { kind: 'text', value: 'rate limit' }),
			IDENTITIES
		);
		expect(f.q).toBe('timeout,rate limit');
	});

	test('a single text bubble is unchanged from the old free-text behaviour', () => {
		expect(searchToFilters(value({ kind: 'text', value: 'pull request' }), IDENTITIES).q).toBe(
			'pull request'
		);
	});

	test('filters and text compose into one filter set', () => {
		const f = searchToFilters(
			value(
				{ kind: 'filter', key: 'result', op: '=', value: 'error' },
				{ kind: 'text', value: 'timeout' },
				{ kind: 'filter', key: 'event', op: '~', value: 'action' }
			),
			IDENTITIES
		);
		expect(f.is_error).toBe(true);
		expect(f.action_contains).toBe('action');
		expect(f.q).toBe('timeout');
	});

	test('repeated tag filters narrow, and stay separate from q', () => {
		const f = searchToFilters(
			value(
				{ kind: 'filter', key: 'tag', op: '=', value: 'sql:write' },
				{ kind: 'filter', key: 'tag', op: '=', value: 'outcome:error' },
				{ kind: 'text', value: 'orders' }
			),
			IDENTITIES
		);
		expect(f.tag).toBe('sql:write,outcome:error');
		expect(f.q).toBe('orders');
	});

	test('an unresolvable agent name becomes its own q term, not a welded phrase', () => {
		const f = searchToFilters(
			value(
				{ kind: 'text', value: 'timeout' },
				{ kind: 'filter', key: 'agent', op: '=', value: 'ghost' }
			),
			IDENTITIES
		);
		// Space-joining these would search for the literal "timeout ghost".
		expect(f.q).toBe('timeout,ghost');
	});

	test('user = me resolves to the current user', () => {
		expect(
			searchToFilters(value({ kind: 'filter', key: 'user', op: '=', value: 'me' }), IDENTITIES, ME)
				.owner_user_id
		).toBe(ME.id);
	});

	test('no terms means no filters', () => {
		expect(searchToFilters({ terms: [] }, IDENTITIES)).toEqual({});
	});
});

test.describe('filtersToSearch', () => {
	test('a comma-joined q comes back as one bubble per term', () => {
		const v = filtersToSearch({ q: 'timeout,rate limit' }, IDENTITIES);
		expect(v.terms).toEqual([
			{ kind: 'text', value: 'timeout' },
			{ kind: 'text', value: 'rate limit' }
		]);
	});

	test('an absent or empty q yields no text bubbles', () => {
		expect(filtersToSearch({}, IDENTITIES).terms).toEqual([]);
		expect(filtersToSearch({ q: '' }, IDENTITIES).terms).toEqual([]);
	});

	test('an exact agent id reverses to an agent filter', () => {
		const v = filtersToSearch({ identity_id: IDENTITIES[1].id }, IDENTITIES);
		expect(v.terms).toEqual([{ kind: 'filter', key: 'agent', op: '=', value: 'scout' }]);
	});
});

test.describe('commas inside a text term', () => {
	test('a term containing a comma stays one bubble across the round trip', () => {
		const original = value({ kind: 'text', value: 'New York, NY' });
		const f = searchToFilters(original, IDENTITIES);
		// Escaped on the wire so the server splits on the unescaped comma only.
		expect(f.q).toBe('New York\\, NY');
		expect(filtersToSearch(f, IDENTITIES).terms).toEqual(original.terms);
	});

	test('a comma-bearing term still ANDs with an ordinary one', () => {
		const f = searchToFilters(
			value({ kind: 'text', value: 'a,b' }, { kind: 'text', value: 'c' }),
			IDENTITIES
		);
		expect(f.q).toBe('a\\,b,c');
		expect(splitQTerms(f.q!)).toEqual(['a,b', 'c']);
	});

	test('backslashes survive, and a stray one is not eaten', () => {
		expect(splitQTerms(escapeQTerm('C:\\path'))).toEqual(['C:\\path']);
		// `\d` is not an escape sequence — keep both characters.
		expect(splitQTerms('\\d+')).toEqual(['\\d+']);
	});

	test('unescaped commas still separate terms', () => {
		expect(splitQTerms('a,b, c ,,')).toEqual(['a', 'b', 'c']);
	});
});

test.describe('round trip', () => {
	test('filters and text survive a URL round trip', () => {
		const original = value(
			{ kind: 'filter', key: 'result', op: '=', value: 'error' },
			{ kind: 'text', value: 'timeout' },
			{ kind: 'filter', key: 'tag', op: '=', value: 'sql:write' },
			{ kind: 'text', value: 'orders' }
		);
		const back = filtersToSearch(searchToFilters(original, IDENTITIES, ME), IDENTITIES, ME);
		// Compared as a set: AuditFilters is an unordered bag, so text bubbles
		// always come back last rather than in their typed position.
		expect(new Set(back.terms.map((t) => JSON.stringify(t)))).toEqual(
			new Set(original.terms.map((t) => JSON.stringify(t)))
		);
	});
});
