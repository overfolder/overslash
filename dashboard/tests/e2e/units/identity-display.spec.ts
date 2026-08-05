// Pure-logic checks for the identity label helper — no browser, no stack.
//
// `formatIdentity` decides whether the IdP display name is worth showing next
// to the email. The interesting cases all come from how the backend fills
// `identity.name`, so they are pinned here rather than left to a screenshot to
// notice.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import {
	formatIdentity,
	identityInitials,
	shortEmail
} from '../../../src/lib/identityDisplay';

const ACME = ['acme.com'];

test.describe('shortEmail', () => {
	test('strips the domain only when exactly one is allowed', () => {
		expect(shortEmail('ada@acme.com', ACME)).toBe('ada');
		expect(shortEmail('ada@acme.com', [])).toBe('ada@acme.com');
		expect(shortEmail('ada@acme.com', ['acme.com', 'acme.io'])).toBe('ada@acme.com');
	});

	test('leaves addresses on other domains alone', () => {
		expect(shortEmail('alex@partner.io', ACME)).toBe('alex@partner.io');
	});

	test('normalizes both sides before comparing, but preserves local-part case', () => {
		expect(shortEmail('Ada@ACME.com', ['@Acme.com '])).toBe('Ada');
	});

	test('survives malformed addresses', () => {
		expect(shortEmail('nodomain', ACME)).toBe('nodomain');
		expect(shortEmail('@acme.com', ACME)).toBe('@acme.com');
		// Quoted local parts may contain '@' — split on the last one.
		expect(shortEmail('"a@b"@acme.com', ACME)).toBe('"a@b"');
	});
});

test.describe('formatIdentity', () => {
	test('a real display name becomes the secondary line', () => {
		const d = formatIdentity(
			{ name: 'Ada Lovelace', email: 'ada@acme.com', kind: 'user' },
			ACME
		);
		expect(d).toEqual({
			primary: 'ada',
			secondary: 'Ada Lovelace',
			title: 'ada@acme.com · Ada Lovelace'
		});
	});

	test('an IdP with no name claim leaves name === email — no secondary', () => {
		// provisioning.rs: `display_name = userinfo.name.unwrap_or(&userinfo.email)`.
		// Magic-link sign-in (name: None) lands here too.
		const d = formatIdentity(
			{ name: 'ada@acme.com', email: 'ada@acme.com', kind: 'user' },
			ACME
		);
		expect(d.secondary).toBeNull();
		expect(d.primary).toBe('ada');
		expect(d.title).toBe('ada@acme.com');
	});

	test('a pending invite leaves name === local part — no secondary either way', () => {
		// org_invites.rs seeds `name = email.split('@').next()`. Suppressing this
		// must not depend on whether the domain is stripped.
		const invited = { name: 'ada', email: 'ada@acme.com', kind: 'user' };
		expect(formatIdentity(invited, ACME).secondary).toBeNull();
		expect(formatIdentity(invited, []).secondary).toBeNull();
		expect(formatIdentity(invited, []).primary).toBe('ada@acme.com');
	});

	test('agents keep their name and gain no secondary', () => {
		const d = formatIdentity({ name: 'research-agent', kind: 'agent' }, ACME);
		expect(d).toEqual({
			primary: 'research-agent',
			secondary: null,
			title: 'research-agent'
		});
	});

	test('a user with no email falls back to the name', () => {
		const d = formatIdentity({ name: 'teammate', email: null, kind: 'user' }, ACME);
		expect(d.primary).toBe('teammate');
		expect(d.secondary).toBeNull();
	});

	test('a blank display name is treated as absent', () => {
		const d = formatIdentity({ name: '   ', email: 'ada@acme.com', kind: 'user' }, ACME);
		expect(d.secondary).toBeNull();
	});
});

test.describe('identityInitials', () => {
	test('prefers a real display name', () => {
		expect(identityInitials({ name: 'Ada Lovelace', email: 'ada@acme.com' })).toBe('AL');
		expect(identityInitials({ name: 'Dev User', email: 'dev@overslash.local' })).toBe('DU');
	});

	test('falls back to the email local part when the name is the address', () => {
		expect(identityInitials({ name: 'ada@acme.com', email: 'ada@acme.com' })).toBe('AD');
	});

	test('agents use their name', () => {
		expect(identityInitials({ name: 'research-agent', kind: 'agent' })).toBe('RE');
	});

	test('never returns empty', () => {
		expect(identityInitials({ name: '', email: null })).toBe('?');
	});
});
