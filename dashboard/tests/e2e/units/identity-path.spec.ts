// Pure-logic checks for the SPIFFE path helper — no browser, no stack.
//
// `formatIdentityPath` produces the audit log's Agent-column hover. Since the
// path carries the IdP display name frozen at write time, the audit row passes
// a resolver that relabels `user` units by email. The no-resolver default is
// still part of the exported contract, so it is pinned here too.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import { formatIdentityPath } from '../../../src/lib/identityPath';

const PATH = 'spiffe://acme/user/Ada Lovelace/agent/henry/sub_agent/researcher';
const IDS = [
	'11111111-1111-1111-1111-111111111111',
	'22222222-2222-2222-2222-222222222222',
	'33333333-3333-3333-3333-333333333333'
];

test.describe('formatIdentityPath', () => {
	test('without a resolver, renders the path names', () => {
		expect(formatIdentityPath(PATH)).toBe('Ada Lovelace / henry / researcher');
		expect(formatIdentityPath(PATH, IDS)).toBe('Ada Lovelace / henry / researcher');
		expect(formatIdentityPath(null)).toBe('');
	});

	test('applies the resolver per unit, with id and kind', () => {
		const seen: Array<[string | null, string, string]> = [];
		const out = formatIdentityPath(PATH, IDS, (id, name, kind) => {
			seen.push([id, name, kind]);
			return kind === 'user' ? 'ada' : name;
		});
		expect(out).toBe('ada / henry / researcher');
		expect(seen).toEqual([
			[IDS[0], 'Ada Lovelace', 'user'],
			[IDS[1], 'henry', 'agent'],
			[IDS[2], 'researcher', 'sub_agent']
		]);
	});

	test('passes a null id when the row carries no aligned ids', () => {
		// Legacy audit rows predate `identity_path_ids`; the resolver can't look
		// anything up, so it has to fall back to the name.
		expect(formatIdentityPath(PATH, [], (id, name) => id ?? name)).toBe(
			'Ada Lovelace / henry / researcher'
		);
	});

	test('falls back per unit when only some ids resolve', () => {
		const known = new Map([[IDS[0], 'ada']]);
		expect(
			formatIdentityPath(PATH, IDS, (id, name) => (id && known.get(id)) || name)
		).toBe('ada / henry / researcher');
	});
});
