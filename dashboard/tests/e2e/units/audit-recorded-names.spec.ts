// Pure-logic checks for reconciling the names recorded on an audit row (D59)
// against the live identity chain — no browser, no stack.
//
// The case worth guarding is the human acting directly. `identityUnits` returns
// `leaf: null` for a user-only path, so a comparison written against the leaf
// alone silently never fires for those rows — and a user rename is the common
// one, since their display name is refreshed from their IdP on every sign-in
// while an agent has to be renamed deliberately through the API.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import { recordedNames, type AuditEntry } from '../../../src/routes/audit/types';
import { identityUnits } from '../../../src/lib/identityPath';

function entry(over: Partial<AuditEntry> = {}): AuditEntry {
	return {
		id: 'e1',
		identity_id: 'i1',
		identity_name: null,
		owner_user_name: null,
		identity_path: null,
		identity_path_ids: [],
		action: 'secret.put',
		description: null,
		resource_type: null,
		resource_id: null,
		detail: {},
		ip_address: null,
		created_at: '2026-08-11T12:00:00Z',
		impersonated_by_identity_id: null,
		impersonated_by_name: null,
		impersonated_by_path: null,
		impersonated_by_path_ids: [],
		tags: [],
		...over
	};
}

const AGENT_PATH = 'spiffe://acme/user/alice/agent/henry';
const USER_PATH = 'spiffe://acme/user/alice';

test('a renamed agent reports against the leaf', () => {
	const units = identityUnits(AGENT_PATH, ['u1', 'a1']);
	const names = recordedNames(
		entry({ identity_name: 'deploy-bot', owner_user_name: 'alice' }),
		units
	);
	expect(names.actor).toMatchObject({ recorded: 'deploy-bot', live: 'henry', renamed: true });
	expect(names.actor.label).toBe('deploy-bot');
	expect(names.user.renamed).toBe(false);
	expect(names.actorIsAgent).toBe(true);
});

test('a renamed user acting directly is reported, not silently skipped', () => {
	const units = identityUnits(USER_PATH, ['u1']);
	expect(units.leaf).toBeNull(); // the reason a leaf-only comparison misses this
	const names = recordedNames(
		entry({ identity_name: 'alice.old', owner_user_name: 'alice.old' }),
		units
	);
	expect(names.actor).toMatchObject({ recorded: 'alice.old', live: 'alice', renamed: true });
	expect(names.actorIsAgent).toBe(false);
});

test('an unrenamed identity reports no divergence', () => {
	const units = identityUnits(AGENT_PATH, ['u1', 'a1']);
	const names = recordedNames(entry({ identity_name: 'henry', owner_user_name: 'alice' }), units);
	expect(names.actor.renamed).toBe(false);
	expect(names.user.renamed).toBe(false);
});

test('a renamed owner is reported separately from the actor', () => {
	const units = identityUnits(AGENT_PATH, ['u1', 'a1']);
	const names = recordedNames(entry({ identity_name: 'henry', owner_user_name: 'alice.old' }), units);
	expect(names.actor.renamed).toBe(false);
	expect(names.user).toMatchObject({ recorded: 'alice.old', live: 'alice', renamed: true });
});

test('rows written before the columns existed fall back to the live names', () => {
	const units = identityUnits(AGENT_PATH, ['u1', 'a1']);
	const names = recordedNames(entry(), units);
	expect(names.actor.renamed).toBe(false);
	expect(names.actor.label).toBe('henry');
});

test('a deleted identity has a record but no live chain, and is not "renamed"', () => {
	const units = identityUnits(null, []);
	const names = recordedNames(
		entry({ identity_path: null, identity_name: 'gone-bot', owner_user_name: 'alice' }),
		units
	);
	expect(names.actor).toMatchObject({ recorded: 'gone-bot', live: null, renamed: false });
	// The label is still the recorded name — that row used to render nothing.
	expect(names.actor.label).toBe('gone-bot');
});
