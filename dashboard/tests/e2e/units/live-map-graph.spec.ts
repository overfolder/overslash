// Pure-logic checks for the Live Map's structural graph — no browser, no stack.
//
// Two rules here are easy to get subtly wrong and expensive to notice on a
// canvas: which cluster a service instance belongs to, and which ball a call
// named only by service *name* lands on. Instance names are unique per owner,
// not per org, so an admin's listing can hold three rows called `gcal`; if the
// graph keys them by name they collapse onto one ball, and a ball can only sit
// inside one ownership container.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import { buildGraph, RAW_HTTP_ID } from '../../../src/lib/components/map/graph';
import type { Identity, ServiceInstanceSummary } from '../../../src/lib/types';

const ANA = 'id-ana';
const BRUNO = 'id-bruno';
const ANA_AGENT = 'id-ana-agent';
const ANA_SUB = 'id-ana-sub';
const BRUNO_AGENT = 'id-bruno-agent';

function user(id: string, name: string, email?: string): Identity {
	return {
		id,
		org_id: 'org',
		name,
		email,
		kind: 'user',
		external_id: null,
		parent_id: null,
		depth: 0,
		owner_id: null,
		inherit_permissions: false
	};
}

function agent(id: string, name: string, parent: string, owner: string, depth = 1): Identity {
	return {
		id,
		org_id: 'org',
		name,
		kind: depth === 1 ? 'agent' : 'sub_agent',
		external_id: null,
		parent_id: parent,
		depth,
		owner_id: owner,
		inherit_permissions: true
	};
}

function service(name: string, owner?: string): ServiceInstanceSummary {
	return {
		id: `svc-${owner ?? 'org'}-${name}`,
		name,
		template_source: 'global',
		template_key: name,
		status: 'active',
		is_system: false,
		owner_identity_id: owner,
		use_default_connection: true
	};
}

const identities = [
	user(ANA, 'Ana Ruiz', 'ana@acme.com'),
	user(BRUNO, 'bruno'),
	agent(ANA_AGENT, 'research-bot', ANA, ANA),
	agent(ANA_SUB, 'fetcher', ANA_AGENT, ANA, 2),
	agent(BRUNO_AGENT, 'triage', BRUNO, BRUNO)
];

const OPEN = { users: false, agents: false, subagents: false };

const build = (services: ServiceInstanceSummary[], extra: string[] = [], domains: string[] = []) =>
	buildGraph(identities, services, extra, OPEN, {}, domains);

test.describe('labels', () => {
	test('a user is named by email, domain-stripped like the users list', () => {
		expect(build([], [], ['acme.com']).byId.get(ANA)!.label).toBe('ana');
		// Several allowed domains: the domain carries information, so it stays.
		expect(build([], [], ['acme.com', 'other.com']).byId.get(ANA)!.label).toBe('ana@acme.com');
	});

	test('the full handle survives as the title, and drives the ball monogram', () => {
		const n = build([], [], ['acme.com']).byId.get(ANA)!;
		expect(n.title).toBe('ana@acme.com · Ana Ruiz');
		expect(n.mono).toBe('A');
	});

	test('an email-less user and an agent keep their name', () => {
		const g = build([], [], ['acme.com']);
		expect(g.byId.get(BRUNO)!.label).toBe('bruno');
		expect(g.byId.get(ANA_AGENT)!.label).toBe('research-bot');
	});
});

test.describe('ownership clusters', () => {
	test("a user-level instance joins its owner's cluster", () => {
		const g = build([service('gcal', ANA)]);
		const node = [...g.byId.values()].find((n) => n.kind === 'service' && n.label === 'gcal');
		expect(node).toBeTruthy();
		expect(g.rootOf.get(node!.id)).toBe(ANA);
	});

	test('an org-level instance belongs to no cluster', () => {
		const g = build([service('github')]);
		const node = [...g.byId.values()].find((n) => n.kind === 'service');
		expect(node!.owner).toBeUndefined();
		expect(g.rootOf.has(node!.id)).toBe(false);
	});

	test('two owners of the same name get one ball each, in their own boxes', () => {
		const g = build([service('gcal', ANA), service('gcal', BRUNO)]);
		const balls = [...g.byId.values()].filter((n) => n.kind === 'service');
		expect(balls).toHaveLength(2);
		expect(new Set(balls.map((n) => n.id)).size).toBe(2);
		expect(new Set(balls.map((n) => g.rootOf.get(n.id)))).toEqual(new Set([ANA, BRUNO]));
	});

	test("an instance owned by an agent roots to that agent's user", () => {
		// `on_behalf_of` binds the instance to the agent, but containers are
		// keyed by user, so it has to climb the tree.
		const g = build([service('notion', ANA_SUB)]);
		const node = [...g.byId.values()].find((n) => n.kind === 'service');
		expect(node!.owner).toBe(ANA);
		expect(g.rootOf.get(node!.id)).toBe(ANA);
	});

	test('an owner outside the returned set leaves the instance unclustered', () => {
		const g = build([service('jira', 'id-archived')]);
		const node = [...g.byId.values()].find((n) => n.kind === 'service');
		// Someone's, but not anyone we can draw a box around.
		expect(g.rootOf.get(node!.id)).toBe('id-archived');
		expect(g.structSet.has('id-archived')).toBe(false);
	});
});

test.describe('layout', () => {
	test('the owned-service gap the physics springs to shrinks with the folded tree', () => {
		const open = buildGraph(identities, [], [], OPEN, {});
		const folded = buildGraph(identities, [], [], { ...OPEN, subagents: true }, {});
		// One subagent level to clear when it is drawn, none when it is not.
		expect(open.ownedServiceGap).toBeGreaterThan(folded.ownedServiceGap);
	});

	test("an owned service's target sits that far from its owner, not from the centre", () => {
		const g = build([service('gcal', ANA)]);
		const svc = [...g.byId.values()].find((n) => n.kind === 'service')!;
		const a = g.targets.get(ANA)!;
		const b = g.targets.get(svc.id)!;
		expect(Math.hypot(b.x - a.x, b.y - a.y)).toBeCloseTo(g.ownedServiceGap, 6);
	});

	test('an org-level instance keeps the shared ring, clear of the owned arc', () => {
		const g = build([service('gcal', ANA), service('github')]);
		const org = [...g.byId.values()].find((n) => n.kind === 'service' && !n.owner)!;
		const owned = [...g.byId.values()].find((n) => n.kind === 'service' && n.owner)!;
		const r = (id: string) => {
			const t = g.targets.get(id)!;
			return Math.hypot(t.x, t.y);
		};
		expect(r(org.id)).toBeGreaterThan(r(owned.id));
	});
});

test.describe('serviceIdFor', () => {
	test("the caller's own instance shadows the org one of the same name", () => {
		const g = build([service('gcal'), service('gcal', ANA)]);
		const mine = g.serviceIdFor('gcal', ANA_AGENT);
		expect(g.byId.get(mine)!.owner).toBe(ANA);
	});

	test('a caller who owns none falls through to the org instance', () => {
		const g = build([service('gcal'), service('gcal', ANA)]);
		const theirs = g.serviceIdFor('gcal', BRUNO_AGENT);
		expect(g.byId.get(theirs)!.owner).toBeUndefined();
	});

	test('a sub-agent resolves through its owner user, not its parent agent', () => {
		const g = build([service('gcal'), service('gcal', ANA)]);
		expect(g.serviceIdFor('gcal', ANA_SUB)).toBe(g.serviceIdFor('gcal', ANA_AGENT));
	});

	test('a name nothing matches lands unqualified, in no container', () => {
		const g = build([service('gcal', ANA)]);
		const id = g.serviceIdFor('stripe', BRUNO_AGENT);
		expect(id).toBe('service:stripe');
		// Fed back as an extra, it becomes a ball on the shared ring.
		const g2 = build([service('gcal', ANA)], [id]);
		expect(g2.byId.get(id)!.unlisted).toBe(true);
		expect(g2.rootOf.has(id)).toBe(false);
	});

	test('a call naming no service is raw HTTP', () => {
		const g = build([]);
		expect(g.serviceIdFor(null, ANA_AGENT)).toBe(RAW_HTTP_ID);
		expect(g.serviceIdFor(undefined)).toBe(RAW_HTTP_ID);
	});

	test('an extra is dropped once the fleet refetch lists the same name', () => {
		// Seen in traffic first, listed a refetch later: one instance, one ball.
		const g = build([service('gcal', ANA)], ['service:gcal']);
		const balls = [...g.byId.values()].filter((n) => n.kind === 'service');
		expect(balls).toHaveLength(1);
		expect(balls[0].unlisted).toBeUndefined();
	});
});
