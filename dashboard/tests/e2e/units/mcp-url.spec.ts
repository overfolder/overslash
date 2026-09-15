// Pure-logic checks for the MCP endpoint the dashboard hands the operator.
//
// This URL is not cosmetic. Per D26 (docs/design/mcp-enrollment-org-scoping.md)
// the org subdomain is an *enforced* enrollment lock: an agent enrolled through
// `<slug>.api.overslash.com/mcp` is guaranteed to land in that org. Get the
// mapping wrong and we either hand out a dead URL or — for a self-hoster — a
// command pointing at somebody else's server. Neither is something a screenshot
// would catch, so the mapping is pinned here, host by host.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import { ownMcpUrlFor } from '../../../src/lib/env';

test('prod org subdomain keeps the slug', () => {
	expect(ownMcpUrlFor('https://reveni.app.overslash.com', 'reveni', true)).toBe(
		'https://reveni.api.overslash.com/mcp'
	);
});

test('prod apex still hands out the org-scoped URL', () => {
	// The multi-org hub is where a user lands by default, but the command we
	// give them should still pin the client to the org they are looking at.
	expect(ownMcpUrlFor('https://app.overslash.com', 'reveni', true)).toBe(
		'https://reveni.api.overslash.com/mcp'
	);
});

test('dev maps onto the dev apex', () => {
	expect(ownMcpUrlFor('https://reveni-dev.app.dev.overslash.com', 'reveni-dev', true)).toBe(
		'https://reveni-dev.api.dev.overslash.com/mcp'
	);
	expect(ownMcpUrlFor('https://app.dev.overslash.com', 'reveni-dev', true)).toBe(
		'https://reveni-dev.api.dev.overslash.com/mcp'
	);
});

test('a dev host is never mistaken for prod', () => {
	// `.dev.` inside the host is the whole difference between pointing an
	// operator at the dev cloud and pointing them at production.
	expect(ownMcpUrlFor('https://acme.app.dev.overslash.com', 'acme', true)).toContain('api.dev.');
	expect(ownMcpUrlFor('https://acme.app.overslash.com', 'acme', true)).not.toContain('api.dev.');
});

test('hosts we do not recognise fall back to their own origin', () => {
	// A self-hosted `overslash web` serves the dashboard and the API from one
	// origin, so its own origin is the right answer — and guessing an
	// overslash.com URL there would point the operator at someone else's
	// server. Vercel previews and local dev both proxy /mcp onward, so the
	// same fallback is correct for them too.
	expect(ownMcpUrlFor('https://overslash.acme-corp.internal', 'acme', true)).toBe(
		'https://overslash.acme-corp.internal/mcp'
	);
	expect(ownMcpUrlFor('http://localhost:7171', 'acme', true)).toBe('http://localhost:7171/mcp');
	expect(ownMcpUrlFor('http://localhost:5173', 'acme', true)).toBe('http://localhost:5173/mcp');
	expect(ownMcpUrlFor('https://dashboard-git-foo.vercel.app', 'acme', true)).toBe(
		'https://dashboard-git-foo.vercel.app/mcp'
	);
	// The e2e stack's wildcard suffix is not ours to rewrite either.
	expect(ownMcpUrlFor('http://acme.app.localtest.me:4173', 'acme', true)).toBe(
		'http://acme.app.localtest.me:4173/mcp'
	);
});

test('no slug falls back to the origin, never to a "null" subdomain', () => {
	// `org_slug` is nullable on MeIdentity; the apex `/mcp` is rewritten onto
	// the right backend by vercel.json, so the origin is a working URL.
	expect(ownMcpUrlFor('https://app.overslash.com', null, true)).toBe('https://app.overslash.com/mcp');
	expect(ownMcpUrlFor('https://app.dev.overslash.com', null, true)).toBe(
		'https://app.dev.overslash.com/mcp'
	);
});

test('an unusable slug falls back to the origin', () => {
	// Two callers land here: a personal org, which subdomain_middleware 404s
	// as `personal_org_unreachable`; and a session where we cannot tell
	// (`memberships` is absent on pre-multi-org tokens). Both must take the
	// origin — a slug URL would be dead with nothing in the UI to explain it.
	expect(ownMcpUrlFor('https://app.overslash.com', 'ada', false)).toBe(
		'https://app.overslash.com/mcp'
	);
	expect(ownMcpUrlFor('https://acme.app.overslash.com', 'acme', false)).toBe(
		'https://acme.app.overslash.com/mcp'
	);
});

test('an empty origin degrades to a relative path, not a guessed one', () => {
	// The SSR branch passes '' rather than a sentinel hostname, so a
	// mis-timed render can never invent a production URL.
	expect(ownMcpUrlFor('', 'acme', true)).toBe('/mcp');
});

test('a trailing slash on the origin does not double up', () => {
	expect(ownMcpUrlFor('https://app.overslash.com/', null, true)).toBe('https://app.overslash.com/mcp');
});

test('an unparseable origin degrades to a relative path', () => {
	expect(ownMcpUrlFor('not a url', 'acme', true)).toBe('/mcp');
});
