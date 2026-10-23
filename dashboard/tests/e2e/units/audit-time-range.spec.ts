// Pure-logic checks for the audit log's time window — no browser, no stack.
//
// The window is the one filter every audit query carries, and it rides the URL:
// a relative preset has to survive as a preset (so a shared link keeps meaning
// "the last hour"), a custom range as fixed instants, and a URL naming neither
// has to land on the default rather than on the org's whole history.
import { test, expect } from '@playwright/test';
import {
	DEFAULT_RANGE,
	fromLocalInput,
	rangeFromSearchParams,
	rangeToParams,
	resolveRange,
	toLocalInput,
	widerPreset
} from '../../../src/routes/audit/timeRange';
import { exportQuery } from '../../../src/routes/audit/types';

const NOW = new Date('2026-10-23T12:00:00.000Z');

test.describe('rangeFromSearchParams', () => {
	test('no window in the URL means the 24h default', () => {
		expect(rangeFromSearchParams(new URLSearchParams(''))).toEqual(DEFAULT_RANGE);
		expect(DEFAULT_RANGE).toEqual({ kind: 'relative', preset: '24h' });
	});

	test('a preset wins over stray since/until', () => {
		const p = new URLSearchParams('range=1h&since=2026-01-01T00:00:00Z');
		expect(rangeFromSearchParams(p)).toEqual({ kind: 'relative', preset: '1h' });
	});

	test('an unknown preset falls back to the default', () => {
		expect(rangeFromSearchParams(new URLSearchParams('range=30d'))).toEqual(DEFAULT_RANGE);
	});

	test('since/until is a custom range; since alone runs to now', () => {
		const since = '2026-10-20T14:00:00.000Z';
		const until = '2026-10-21T09:30:00.000Z';
		expect(rangeFromSearchParams(new URLSearchParams({ since, until }))).toEqual({
			kind: 'absolute',
			since,
			until
		});
		expect(rangeFromSearchParams(new URLSearchParams({ since }))).toEqual({
			kind: 'absolute',
			since
		});
	});

	test('a garbage instant is ignored rather than sent to the API', () => {
		expect(rangeFromSearchParams(new URLSearchParams('since=yesterday'))).toEqual(DEFAULT_RANGE);
	});
});

test.describe('round trip', () => {
	for (const range of [
		{ kind: 'relative', preset: '5m' },
		{ kind: 'relative', preset: '7d' },
		{ kind: 'absolute', since: '2026-10-20T14:00:00.000Z', until: '2026-10-21T09:30:00.000Z' }
	] as const) {
		test(`${JSON.stringify(range)} survives the URL`, () => {
			const p = new URLSearchParams(rangeToParams(range));
			expect(rangeFromSearchParams(p)).toEqual(range);
		});
	}
});

test.describe('resolveRange', () => {
	test('a preset resolves back from now', () => {
		expect(resolveRange({ kind: 'relative', preset: '1h' }, NOW)).toEqual({
			since: '2026-10-23T11:00:00.000Z',
			until: '2026-10-23T12:00:00.000Z'
		});
		expect(resolveRange({ kind: 'relative', preset: '7d' }, NOW).since).toBe(
			'2026-10-16T12:00:00.000Z'
		);
	});

	test('a custom range is fixed; an open end resolves to now', () => {
		const since = '2026-10-20T14:00:00.000Z';
		expect(resolveRange({ kind: 'absolute', since, until: '2026-10-21T00:00:00.000Z' }, NOW)).toEqual({
			since,
			until: '2026-10-21T00:00:00.000Z'
		});
		expect(resolveRange({ kind: 'absolute', since }, NOW).until).toBe(NOW.toISOString());
	});
});

test('widerPreset steps up and stops at 7d', () => {
	expect(widerPreset('5m')).toBe('1h');
	expect(widerPreset('24h')).toBe('7d');
	expect(widerPreset('7d')).toBeNull();
});

test('datetime-local values convert through local time losslessly to the minute', () => {
	const iso = '2026-10-20T14:05:00.000Z';
	expect(fromLocalInput(toLocalInput(iso))).toBe(iso);
	expect(fromLocalInput('')).toBeNull();
});

test('exportQuery carries filters and window, never paging', () => {
	const qs = new URLSearchParams(
		exportQuery(
			{
				action: 'action.executed',
				tag: 'sql:write',
				since: '2026-10-22T12:00:00.000Z',
				until: '2026-10-23T12:00:00.000Z'
			},
			'jsonl'
		)
	);
	expect(qs.get('format')).toBe('jsonl');
	expect(qs.get('action')).toBe('action.executed');
	expect(qs.get('tag')).toBe('sql:write');
	expect(qs.get('since')).toBe('2026-10-22T12:00:00.000Z');
	expect(qs.get('until')).toBe('2026-10-23T12:00:00.000Z');
	expect(qs.has('limit')).toBe(false);
	expect(qs.has('before')).toBe(false);
});
