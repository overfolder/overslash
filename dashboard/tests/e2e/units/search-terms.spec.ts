// Pure-logic checks for the search bar's term model — no browser, no stack.
//
// Every bubble in the bar is a term, and terms AND together. The parsing and
// dedup rules decide what a keystroke turns into, so they are pinned here
// rather than left to a screenshot to notice.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import {
	addTerm,
	addTerms,
	emptySearch,
	filterTerms,
	hasTerm,
	matchesAllText,
	parseSearch,
	removeTermAt,
	sameTerm,
	termToDraft,
	textTerms,
	type SearchValue,
	type Term
} from '../../../src/lib/search/terms';

const KEYS = ['event', 'result', 'tag', 'hidden'];

function value(...terms: Term[]): SearchValue {
	return { terms };
}

test.describe('parseSearch', () => {
	test('plain text becomes one bubble, not one per word', () => {
		expect(parseSearch('pull request', KEYS)).toEqual([{ kind: 'text', value: 'pull request' }]);
	});

	test('a known key becomes a filter and leaves no text behind', () => {
		expect(parseSearch('event = action.executed', KEYS)).toEqual([
			{ kind: 'filter', key: 'event', op: '=', value: 'action.executed' }
		]);
	});

	test('keeps typed order across a filter in the middle', () => {
		expect(parseSearch('hello event=x world', KEYS)).toEqual([
			{ kind: 'text', value: 'hello' },
			{ kind: 'filter', key: 'event', op: '=', value: 'x' },
			{ kind: 'text', value: 'world' }
		]);
	});

	test('does not weld fragments that a consumed filter separated', () => {
		// The old single-`freeText` model collapsed these into "hello world".
		const terms = parseSearch('hello event=x world', KEYS);
		expect(textTerms({ terms })).toEqual(['hello', 'world']);
	});

	test('all three operators parse, with or without spaces', () => {
		expect(parseSearch('hidden!=true', KEYS)).toEqual([
			{ kind: 'filter', key: 'hidden', op: '!=', value: 'true' }
		]);
		expect(parseSearch('tag ~ sql', KEYS)).toEqual([
			{ kind: 'filter', key: 'tag', op: '~', value: 'sql' }
		]);
	});

	test('quotes group a value, and are stripped', () => {
		expect(parseSearch('tag="a b"', KEYS)).toEqual([
			{ kind: 'filter', key: 'tag', op: '=', value: 'a b' }
		]);
		expect(parseSearch('"pull request"', KEYS)).toEqual([
			{ kind: 'text', value: 'pull request' }
		]);
	});

	test('an unknown key stays text, wherever it sits', () => {
		expect(parseSearch('foo=bar', KEYS)).toEqual([{ kind: 'text', value: 'foo=bar' }]);
		expect(parseSearch('event=x foo=bar', KEYS)).toEqual([
			{ kind: 'filter', key: 'event', op: '=', value: 'x' },
			{ kind: 'text', value: 'foo=bar' }
		]);
		expect(parseSearch('foo=bar event=x', KEYS)).toEqual([
			{ kind: 'text', value: 'foo=bar' },
			{ kind: 'filter', key: 'event', op: '=', value: 'x' }
		]);
	});

	test('empty and whitespace-only input produce nothing', () => {
		expect(parseSearch('', KEYS)).toEqual([]);
		expect(parseSearch('   ', KEYS)).toEqual([]);
	});

	test('a filter with an empty value is dropped rather than filtering on nothing', () => {
		expect(parseSearch('event=""', KEYS)).toEqual([]);
	});
});

test.describe('term list', () => {
	test('addTerm returns the same object on a duplicate', () => {
		const v = value({ kind: 'text', value: 'foo' });
		// Identity, not just length: the caller skips its emit (and, on the audit
		// page, a refetch) when nothing changed.
		expect(addTerm(v, { kind: 'text', value: 'foo' })).toBe(v);
		expect(addTerm(v, { kind: 'text', value: 'FOO' })).toBe(v);
		expect(addTerm(v, { kind: 'text', value: 'bar' })).not.toBe(v);
	});

	test('text dedup ignores case, filter dedup does not', () => {
		expect(sameTerm({ kind: 'text', value: 'GitHub' }, { kind: 'text', value: 'github' })).toBe(
			true
		);
		expect(
			sameTerm(
				{ kind: 'filter', key: 'tag', op: '=', value: 'SQL' },
				{ kind: 'filter', key: 'tag', op: '=', value: 'sql' }
			)
		).toBe(false);
	});

	test('a text term and a filter that read alike are different bubbles', () => {
		expect(
			sameTerm({ kind: 'text', value: 'tag = x' }, { kind: 'filter', key: 'tag', op: '=', value: 'x' })
		).toBe(false);
	});

	test('empty text is never added', () => {
		const v = emptySearch();
		expect(addTerm(v, { kind: 'text', value: '   ' })).toBe(v);
	});

	test('addTerms preserves order and drops duplicates', () => {
		const v = addTerms(emptySearch(), parseSearch('a event=x a', KEYS));
		expect(v.terms).toEqual([
			{ kind: 'text', value: 'a' },
			{ kind: 'filter', key: 'event', op: '=', value: 'x' }
		]);
	});

	test('removeTermAt drops one term and ignores out-of-range', () => {
		const v = value({ kind: 'text', value: 'a' }, { kind: 'text', value: 'b' });
		expect(removeTermAt(v, 0).terms).toEqual([{ kind: 'text', value: 'b' }]);
		expect(removeTermAt(v, 5)).toBe(v);
		expect(removeTermAt(v, -1)).toBe(v);
	});

	test('hasTerm, filterTerms and textTerms split the list without reordering', () => {
		const v = value(
			{ kind: 'text', value: 'a' },
			{ kind: 'filter', key: 'tag', op: '=', value: 'x' },
			{ kind: 'text', value: 'b' }
		);
		expect(hasTerm(v, { kind: 'filter', key: 'tag', op: '=', value: 'x' })).toBe(true);
		expect(hasTerm(v, { kind: 'filter', key: 'tag', op: '~', value: 'x' })).toBe(false);
		expect(filterTerms(v)).toHaveLength(1);
		expect(textTerms(v)).toEqual(['a', 'b']);
	});
});

test.describe('matchesAllText', () => {
	const fields = ['github', 'ada@acme.com'];

	test('no text terms matches everything', () => {
		expect(matchesAllText(fields, emptySearch())).toBe(true);
	});

	test('every term must match, each possibly in a different field', () => {
		expect(
			matchesAllText(fields, value({ kind: 'text', value: 'git' }, { kind: 'text', value: 'acme' }))
		).toBe(true);
		expect(
			matchesAllText(fields, value({ kind: 'text', value: 'git' }, { kind: 'text', value: 'zzz' }))
		).toBe(false);
	});

	test('a term may not straddle two fields', () => {
		// The reason the helper takes the fields apart instead of joining them.
		expect(matchesAllText(fields, value({ kind: 'text', value: 'github ada' }))).toBe(false);
	});

	test('matching is case-insensitive', () => {
		expect(matchesAllText(fields, value({ kind: 'text', value: 'GitHub' }))).toBe(true);
	});
});

test.describe('termToDraft', () => {
	test('round-trips every term shape back through the parser', () => {
		const terms: Term[] = [
			{ kind: 'text', value: 'pull request' },
			{ kind: 'filter', key: 'event', op: '=', value: 'action.executed' },
			{ kind: 'filter', key: 'tag', op: '~', value: 'a b' },
			{ kind: 'filter', key: 'hidden', op: '!=', value: 'true' }
		];
		for (const t of terms) {
			expect(parseSearch(termToDraft(t), KEYS)).toEqual([t]);
		}
	});

	test('quotes text that would otherwise re-parse as a filter', () => {
		// `foo` is unknown today, but a surface can grow a `foo` key later — the
		// bubble must not silently change kind when it is reopened for editing.
		const t: Term = { kind: 'text', value: 'foo=bar' };
		expect(parseSearch(termToDraft(t), [...KEYS, 'foo'])).toEqual([t]);
	});
});
