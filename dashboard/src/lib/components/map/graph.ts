/**
 * The Live Map's structural graph: who exists and where they sit, with no
 * notion of time or traffic.
 *
 * Two things live here because they are pure and the rest of the map is not.
 * `buildGraph` turns the REST snapshot into nodes, edges and radial target
 * positions; `resolve` collapses a node id onto whichever ancestor is
 * currently standing in for it. Everything downstream — the physics, the
 * canvas, the DOM layer — only ever asks those two questions, so the collapse
 * rules are stated once instead of being re-derived per frame.
 *
 * Positions here are *targets*, not truth. The simulation springs towards
 * them; a dragged node overrides them. See `sim.ts`.
 */
import type { Identity, ServiceInstanceSummary } from '$lib/types';

export type NodeKind = 'user' | 'agent' | 'subagent' | 'service' | 'org';

export interface MapNode {
	id: string;
	kind: NodeKind;
	/** Caption under the ball. */
	label: string;
	/** 1–2 characters inside the ball. */
	mono: string;
	/** The identity's IdP avatar, when it has one. Drawn in place of `mono`;
	 *  agents have none and keep the monogram. */
	picture?: string;
	/** A service's catalog mark (`icon_url`), when its template resolves one.
	 *  Kept separate from `picture` because the two want opposite treatments:
	 *  a face is cropped to fill the circle, a brand logo must not be, and it
	 *  needs a light ground the dark theme's ball does not give it. */
	icon?: string;
	/** Parent in the identity tree — the agent, for a subagent. */
	parent?: string;
	/** The owner *user*, for anything below one. */
	owner?: string;
	/** Descendant count, for the tooltip. */
	sub?: number;
	/** Service instance status, for the tooltip. */
	status?: string;
}

export interface MapEdge {
	id: string;
	from: string;
	to: string;
}

export interface CollapseState {
	users: boolean;
	agents: boolean;
	subagents: boolean;
}

export interface Graph {
	/** Every node, collapsed or not, keyed by id. */
	byId: Map<string, MapNode>;
	/** Only the nodes currently standing on their own. */
	structural: MapNode[];
	structSet: Set<string>;
	edges: MapEdge[];
	/** id → how many descendants are folded into it right now. */
	hidden: Map<string, number>;
	targets: Map<string, { x: number; y: number }>;
	/** id → the user (or the org aggregate) whose cluster it belongs to. */
	rootOf: Map<string, string>;
	resolve(id: string): string;
	closedFor(id: string, kind: NodeKind): boolean;
}

/** The aggregate node users collapse into. */
export const ORG_ID = 'agg:org';
/** Where a call that names no service lands. Mode A raw HTTP names the
 *  synthetic `http` pseudo-service, which *is* a real instance and gets a
 *  node of its own — this is only for a payload with no `service` at all. */
export const RAW_HTTP_ID = 'service:__none__';

/**
 * Wire `service` value from an `action.*` event → node id.
 *
 * That name is not guaranteed to be in the viewer's `listServices()`: an org
 * admin watching the whole org sees calls to user-level instances they cannot
 * themselves list. Those ids come back through `extraServiceIds` so the
 * traffic has somewhere to land instead of disappearing.
 */
export function serviceNodeId(name: string | null | undefined): string {
	return name ? `service:${name}` : RAW_HTTP_ID;
}

// Radii of the concentric rings, in world units. Lifted from the design's
// chosen values; the physics then relaxes everything off them.
const R_USER = 250;
const R_AGENT = 365;
const R_AGENT_COLLAPSED = 300;
const R_SUB_GAP = 85;
/** Service ring, per service. The ring has to clear the agents, but sizing it
 *  by a constant meant three services on a 700-unit circle set the fit radius
 *  and zoomed a small fleet down to something unreadable. */
const R_SERVICE_MIN_GAP = 170;
const R_SERVICE_PER_NODE = 42;
/** Angular spread between siblings, radians. */
const SPREAD_AGENT = 0.42;
const SPREAD_SUB = 0.11;

const polar = (r: number, a: number) => ({ x: Math.cos(a) * r, y: Math.sin(a) * r });

function mono(name: string, chars = 1): string {
	const trimmed = name.trim();
	if (!trimmed) return '·';
	return [...trimmed].slice(0, chars).join('').toUpperCase();
}

/**
 * Nodes for the identity tree.
 *
 * Ring membership is decided by *distance from the owning user*, not by the
 * `kind` column. The two usually agree, but the tree allows a sub-agent under
 * a sub-agent, and a node three levels down belongs on the outer ring
 * regardless of what it calls itself.
 */
function identityNodes(identities: Identity[]): MapNode[] {
	const byId = new Map(identities.map((i) => [i.id, i]));
	const childCount = new Map<string, number>();
	for (const i of identities) {
		if (i.parent_id) childCount.set(i.parent_id, (childCount.get(i.parent_id) ?? 0) + 1);
	}

	return identities.map((i) => {
		if (i.kind === 'user') {
			return {
				id: i.id,
				kind: 'user' as const,
				label: i.name,
				mono: mono(i.name),
				picture: i.picture ?? undefined,
				sub: childCount.get(i.id) ?? 0
			};
		}
		const owner = i.owner_id ?? i.parent_id ?? undefined;
		// Direct child of the owning user → agent ring. Anything deeper is a
		// subagent, whatever `kind` says.
		const parentIsUser = i.parent_id ? byId.get(i.parent_id)?.kind === 'user' : true;
		return {
			id: i.id,
			kind: parentIsUser ? ('agent' as const) : ('subagent' as const),
			label: i.name,
			mono: mono(i.name),
			// Agents are created through the API and have no IdP, so this is
			// almost always undefined — but the column is on every identity,
			// so read it rather than assume.
			picture: i.picture ?? undefined,
			parent: i.parent_id ?? undefined,
			owner,
			sub: childCount.get(i.id) ?? 0
		};
	});
}

function serviceNodes(services: ServiceInstanceSummary[], extraIds: string[]): MapNode[] {
	const nodes: MapNode[] = services.map((s) => ({
		id: `service:${s.name}`,
		kind: 'service' as const,
		label: s.name,
		mono: mono(s.name, 2),
		icon: s.icon_url ?? undefined,
		status: s.status
	}));
	// Added only once traffic has actually used them — a permanent "raw http"
	// ball on the ring of an org that never makes one would be noise.
	const known = new Set(nodes.map((n) => n.id));
	for (const id of extraIds) {
		if (known.has(id)) continue;
		known.add(id);
		const label = id === RAW_HTTP_ID ? 'direct' : id.slice('service:'.length);
		nodes.push({
			id,
			kind: 'service' as const,
			label,
			mono: mono(label, 2),
			status: id === RAW_HTTP_ID ? 'No service named' : 'Seen in traffic'
		});
	}
	return nodes;
}

export function buildGraph(
	identities: Identity[],
	services: ServiceInstanceSummary[],
	/** Service node ids seen on the event stream but absent from `services`. */
	extraServiceIds: string[],
	collapse: CollapseState,
	overrides: Record<string, boolean>
): Graph {
	const idNodes = identityNodes(identities);
	const svcNodes = serviceNodes(services, extraServiceIds);
	const all = [...idNodes, ...svcNodes];

	const users = idNodes.filter((n) => n.kind === 'user');
	const orgNode: MapNode = {
		id: ORG_ID,
		kind: 'org',
		label: `${users.length} users`,
		mono: String(users.length)
	};

	const byId = new Map<string, MapNode>(all.map((n) => [n.id, n]));
	byId.set(ORG_ID, orgNode);

	// A node is "closed" when its children are folded into it. A per-node
	// override always wins over the global chip, so expanding one agent
	// doesn't require expanding every agent.
	const closedFor = (id: string, kind: NodeKind): boolean => {
		const o = overrides[id];
		if (o != null) return o;
		return kind === 'user' || kind === 'org' ? collapse.agents : collapse.subagents;
	};

	// Walk up until we hit something that is standing on its own. Depth is
	// bounded by the identity tree, and `seen` guards against a cycle that a
	// corrupt `parent_id` could otherwise turn into a hang.
	const resolve = (id: string): string => {
		const seen = new Set<string>();
		let cur = id;
		for (;;) {
			if (seen.has(cur)) return cur;
			seen.add(cur);
			const n = byId.get(cur);
			if (!n) return cur;
			if (n.kind === 'user') return collapse.users ? ORG_ID : cur;
			if (n.kind === 'agent') {
				if (!n.owner || !closedFor(n.owner, 'user')) return cur;
				cur = n.owner;
				continue;
			}
			if (n.kind === 'subagent') {
				const parentClosed = n.parent ? closedFor(n.parent, 'agent') : false;
				const ownerClosed = n.owner ? closedFor(n.owner, 'user') : false;
				if (!parentClosed && !ownerClosed) return cur;
				cur = n.parent ?? n.owner ?? cur;
				continue;
			}
			return cur;
		}
	};

	const structural: MapNode[] = [];
	if (collapse.users) structural.push(orgNode);
	for (const n of all) if (resolve(n.id) === n.id) structural.push(n);
	const structSet = new Set(structural.map((n) => n.id));

	// Tree edges only. Service edges are activity-derived and are added by the
	// simulation the first time a call traverses them — `/v1/permissions` is
	// per-identity, so deriving them structurally would cost one request per
	// agent for an edge the map can discover for free.
	const seenEdge = new Set<string>();
	const edges: MapEdge[] = [];
	for (const n of idNodes) {
		const parent = n.kind === 'agent' ? n.owner : n.parent;
		if (!parent) continue;
		const a = resolve(parent);
		const b = resolve(n.id);
		if (a === b) continue;
		const id = `${a}>${b}`;
		if (seenEdge.has(id)) continue;
		seenEdge.add(id);
		edges.push({ id, from: a, to: b });
	}

	const hidden = new Map<string, number>();
	for (const n of idNodes) {
		if (n.kind === 'user') continue;
		const r = resolve(n.id);
		if (r !== n.id) hidden.set(r, (hidden.get(r) ?? 0) + 1);
	}

	// ── radial targets ───────────────────────────────────────────────────
	const targets = new Map<string, { x: number; y: number }>();
	targets.set(ORG_ID, { x: 0, y: 0 });

	const userAngle = new Map<string, number>();
	users.forEach((u, i) => {
		const a = -Math.PI / 2 + (i * 2 * Math.PI) / Math.max(1, users.length);
		userAngle.set(u.id, a);
		targets.set(u.id, polar(R_USER, a));
	});

	const agents = idNodes.filter((n) => n.kind === 'agent');
	const agentAngle = new Map<string, number>();
	const agentR = collapse.users ? R_AGENT_COLLAPSED : R_AGENT;
	for (const u of users) {
		const own = agents.filter((a) => a.owner === u.id);
		own.forEach((a, j) => {
			// With users folded into the aggregate there is no per-user angle
			// left to fan out from, so agents ring the centre instead.
			const ang = collapse.users
				? (agents.indexOf(a) / Math.max(1, agents.length)) * 2 * Math.PI - Math.PI / 2
				: (userAngle.get(u.id) ?? 0) + (j - (own.length - 1) / 2) * SPREAD_AGENT;
			agentAngle.set(a.id, ang);
			targets.set(a.id, polar(agentR, ang));
		});
	}
	// Agents whose owner is unknown (or points outside the returned set) would
	// otherwise have no target at all and pile up at the origin.
	agents.forEach((a, i) => {
		if (targets.has(a.id)) return;
		const ang = (i / Math.max(1, agents.length)) * 2 * Math.PI;
		agentAngle.set(a.id, ang);
		targets.set(a.id, polar(agentR, ang));
	});

	// Walk outward one ring at a time rather than placing every subagent
	// against its agent's angle. The tree allows a sub-agent under a sub-agent,
	// and a fixed lookup would give every node below the second level the same
	// angle of zero — a visible pile-up on one spoke.
	const subs = idNodes.filter((n) => n.kind === 'subagent');
	const byParent = new Map<string, MapNode[]>();
	for (const s of subs) {
		const parent = s.parent ?? '';
		byParent.set(parent, [...(byParent.get(parent) ?? []), s]);
	}
	let frontier = agents.map((a) => a.id);
	let ring = 1;
	const placed = new Set(frontier);
	while (frontier.length) {
		const next: string[] = [];
		for (const parent of frontier) {
			const kids = byParent.get(parent) ?? [];
			const base = agentAngle.get(parent) ?? 0;
			kids.forEach((s, k) => {
				if (placed.has(s.id)) return;
				placed.add(s.id);
				const ang = base + (k - (kids.length - 1) / 2) * SPREAD_SUB;
				agentAngle.set(s.id, ang);
				targets.set(s.id, polar(agentR + R_SUB_GAP * ring, ang));
				next.push(s.id);
			});
		}
		frontier = next;
		ring++;
	}
	// Orphans: a parent outside the returned set (archived, or filtered out).
	subs.forEach((s, i) => {
		if (targets.has(s.id)) return;
		targets.set(
			s.id,
			polar(agentR + R_SUB_GAP, (i / Math.max(1, subs.length)) * 2 * Math.PI)
		);
	});

	const svcR = Math.max(
		agentR + R_SUB_GAP * Math.max(1, ring - 1) + R_SERVICE_MIN_GAP,
		svcNodes.length * R_SERVICE_PER_NODE
	);
	svcNodes.forEach((s, i) => {
		const n = svcNodes.length;
		targets.set(s.id, polar(svcR, (i * 2 * Math.PI) / n + Math.PI / n));
	});

	const rootOf = new Map<string, string>();
	for (const n of structural) {
		if (n.kind === 'user' || n.kind === 'org') rootOf.set(n.id, n.id);
		else if (n.kind === 'agent') rootOf.set(n.id, n.owner ? resolve(n.owner) : n.id);
		else if (n.kind === 'subagent') rootOf.set(n.id, n.owner ? resolve(n.owner) : n.id);
	}

	return { byId, structural, structSet, edges, hidden, targets, rootOf, resolve, closedFor };
}
