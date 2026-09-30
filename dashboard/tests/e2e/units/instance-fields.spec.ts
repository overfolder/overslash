// Which instance fields the service form shows up front, and which it keeps
// behind "Show more options".
//
// The contract: nothing the instance needs is ever hidden (required with no
// default from the template or an org layer), a promoted field is always up
// front, and everything else — a field that already has a default — waits.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import {
	endpointIsMain,
	endpointRequired,
	paramIsMain,
	splitParams
} from '../../../src/lib/instance-fields';

const endpoint = { configurable: true, promoted: false };

test('an endpoint with a template default waits behind the disclosure', () => {
	const e = { ...endpoint, defaultUrl: 'https://api.resend.com' };
	expect(endpointRequired(e)).toBe(false);
	expect(endpointIsMain(e)).toBe(false);
});

test('a promoted endpoint is up front even with a default', () => {
	expect(
		endpointIsMain({ ...endpoint, promoted: true, defaultUrl: 'https://cloud.langfuse.com' })
	).toBe(true);
});

test('an endpoint with no default anywhere is required and up front', () => {
	expect(endpointRequired(endpoint)).toBe(true);
	expect(endpointIsMain(endpoint)).toBe(true);
});

test("an org layer's endpoint counts as a default", () => {
	const e = { ...endpoint, inheritedUrl: 'https://gw.acme.example' };
	expect(endpointRequired(e)).toBe(false);
	expect(endpointIsMain(e)).toBe(false);
});

test('a non-configurable endpoint is never shown', () => {
	expect(endpointIsMain({ configurable: false, promoted: true })).toBe(false);
	expect(endpointRequired({ configurable: false, promoted: false })).toBe(false);
});

test('a required param is up front until something supplies it', () => {
	const p = { name: 'mailbox_user', type: 'string', required: true };
	expect(paramIsMain(p, undefined)).toBe(true);
	expect(paramIsMain({ ...p, default: 'ops@acme.example' }, undefined)).toBe(false);
	expect(paramIsMain(p, { mailbox_user: 'ops@acme.example' })).toBe(false);
});

test('splitParams keeps order and sends optional unpromoted params to more', () => {
	const params = [
		{ name: 'a', type: 'string', required: false },
		{ name: 'b', type: 'string', required: false, promoted: true },
		{ name: 'c', type: 'string', required: true }
	];
	const { main, more } = splitParams(params, undefined);
	expect(main.map((p) => p.name)).toEqual(['b', 'c']);
	expect(more.map((p) => p.name)).toEqual(['a']);
});
