// Pure-logic checks for the SPIFFE path helper — no browser, no stack.
//
// `formatIdentityPath` produces the audit log's Agent-column hover. The path's
// user unit is the full email; the audit row passes a resolver that relabels
// it with the domain-stripped form. The no-resolver default is still part of
// the exported contract, so it is pinned here too.
import { test, expect } from '@playwright/test';
import { formatIdentityPath, parseIdentityPath } from '../../../src/lib/identityPath';

const PATH = 'spiffe://acme/user/ada@acme.com/agent/henry/sub_agent/researcher';
const IDS = [
	'11111111-1111-1111-1111-111111111111',
	'22222222-2222-2222-2222-222222222222',
	'33333333-3333-3333-3333-333333333333'
];

test.describe('formatIdentityPath', () => {
	test('without a resolver, renders the path names', () => {
		expect(formatIdentityPath(PATH)).toBe('ada@acme.com / henry / researcher');
		expect(formatIdentityPath(PATH, IDS)).toBe('ada@acme.com / henry / researcher');
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
			[IDS[0], 'ada@acme.com', 'user'],
			[IDS[1], 'henry', 'agent'],
			[IDS[2], 'researcher', 'sub_agent']
		]);
	});

	test('passes a null id when the row carries no aligned ids', () => {
		// Legacy audit rows predate `identity_path_ids`; the resolver can't look
		// anything up, so it has to fall back to the name.
		expect(formatIdentityPath(PATH, [], (id, name) => id ?? name)).toBe(
			'ada@acme.com / henry / researcher'
		);
	});

	test('falls back per unit when only some ids resolve', () => {
		const known = new Map([[IDS[0], 'ada']]);
		expect(
			formatIdentityPath(PATH, IDS, (id, name) => (id && known.get(id)) || name)
		).toBe('ada / henry / researcher');
	});
});

test.describe('parseIdentityPath hrefs', () => {
	test('units link by id when ids are aligned', () => {
		const hrefs = parseIdentityPath(PATH, IDS).map((s) => s.href);
		expect(hrefs).toEqual(['/org', `/users/${IDS[0]}`, `/agents/${IDS[1]}`, `/agents/${IDS[2]}`]);
	});

	test('without ids, a user links by its email segment, never a display name', () => {
		const hrefs = parseIdentityPath(PATH).map((s) => s.href);
		expect(hrefs[1]).toBe('/users/ada%40acme.com');
		expect(hrefs[2]).toBe('/agents/henry');
	});
});
