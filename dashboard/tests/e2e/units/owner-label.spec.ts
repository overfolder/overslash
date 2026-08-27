// Pure-logic checks for the owner-qualifier helper — no browser, no stack.
//
// Service instance names are unique per owner, not per org, so the admin
// "show all users' services" view renders several rows called `gcal`. This
// module decides which of them get their owner spelled out beside the name,
// and what that owner is called. The rules are cheap to get subtly wrong
// (own rows must stay bare, org-level rows have no owner at all), so they are
// pinned here rather than left to a screenshot to notice.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import {
	resolveOwner,
	ownerLabel,
	ownerTitle,
	needsOwnerPrefix,
	qualifyName
} from '../../../src/lib/ownerLabel';
import type { IdentityLike } from '../../../src/lib/identityDisplay';

const ACME = ['acme.com'];

const ME = 'id-me';
const OTHER = 'id-other';
const FOREIGN = 'id-foreign';
const AGENT = 'id-agent';

const identities = new Map<string, IdentityLike>([
	[ME, { name: 'Ada Lovelace', email: 'ada@acme.com', kind: 'user' }],
	[OTHER, { name: 'other1', email: 'other1@acme.com', kind: 'user' }],
	[FOREIGN, { name: 'Otto', email: 'other3@othermail.com', kind: 'user' }],
	[AGENT, { name: 'researcher', kind: 'agent' }]
]);

const owner = (id: string | null | undefined) => resolveOwner(id, identities, ME, ACME);

test.describe('resolveOwner', () => {
	test('no owner id is an org-level row', () => {
		const o = owner(null);
		expect(o.kind).toBe('org');
		expect(ownerLabel(o)).toBe('Org');
		expect(ownerTitle(o)).toBeUndefined();
	});

	test('the viewer own row is self', () => {
		const o = owner(ME);
		expect(o.kind).toBe('self');
		expect(ownerLabel(o)).toBe('You');
		// The title stays lossless even though the label says "You".
		expect(ownerTitle(o)).toBe('ada@acme.com · Ada Lovelace');
	});

	test('another user is labelled by email, domain stripped', () => {
		const o = owner(OTHER);
		expect(o.kind).toBe('other');
		expect(ownerLabel(o)).toBe('other1');
	});

	test('a foreign domain keeps the whole address', () => {
		expect(ownerLabel(owner(FOREIGN))).toBe('other3@othermail.com');
	});

	test('an agent owner keeps its name — agents have no email', () => {
		expect(ownerLabel(owner(AGENT))).toBe('researcher');
	});

	test('an unresolved id degrades to unknown, keeping the raw id in the title', () => {
		const o = owner('id-gone');
		expect(o.kind).toBe('unknown');
		expect(ownerLabel(o)).toBe('unknown');
		expect(ownerTitle(o)).toBe('id-gone');
	});

	test('an empty identity map (non-admin) leaves every owned row unknown', () => {
		const o = resolveOwner(OTHER, new Map(), ME, ACME);
		expect(o.kind).toBe('unknown');
	});
});

test.describe('qualifyName', () => {
	test('only another identity row gets a prefix', () => {
		expect(qualifyName('gcal', owner(null))).toBe('gcal');
		expect(qualifyName('gcal', owner(ME))).toBe('gcal');
		expect(qualifyName('gcal', owner(OTHER))).toBe('other1 / gcal');
		expect(qualifyName('gcal', owner(FOREIGN))).toBe('other3@othermail.com / gcal');
		expect(qualifyName('gcal', owner(AGENT))).toBe('researcher / gcal');
	});

	test('an unresolved owner adds no prefix — a UUID reads worse than nothing', () => {
		expect(qualifyName('gcal', owner('id-gone'))).toBe('gcal');
		expect(needsOwnerPrefix(owner('id-gone'))).toBe(false);
	});

	test('the whole admin list reads as the collision it is', () => {
		const rows = [null, ME, OTHER, FOREIGN].map((id) => qualifyName('gcal', owner(id)));
		expect(rows).toEqual([
			'gcal',
			'gcal',
			'other1 / gcal',
			'other3@othermail.com / gcal'
		]);
	});
});
