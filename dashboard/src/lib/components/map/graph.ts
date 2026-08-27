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
import { formatIdentity } from '$lib/identityDisplay';

export type NodeKind = 'user' | 'agent' | 'subagent' | 'service' | 'org';

export interface MapNode {
	id: string;
	kind: NodeKind;
	/** Caption under the ball. */
	label: string;
	/** 1–2 characters inside the ball. */
	mono: string;
	/** The identity's IdP avatar, when it has one. Drawn in place of `mono`;
	 *  only *users* have one — an agent draws `icon` instead. */
	picture?: string;
	/** The node's brand mark: a service's catalog icon, or an agent's MCP
	 *  client mark (`/icons/client_*.svg`). Kept separate from `picture`
	 *  because the two want opposite treatments: a face is cropped to fill the
	 *  circle, a brand logo must not be, and it needs a light ground the dark
	 *  theme's ball does not give it. */
	icon?: string;
	/** An agent's three hash colours, drawn as a bar between ball and caption
	 *  so siblings sharing a client stay distinguishable. */
	stripe?: string[];
	/** Parent in the identity tree — the agent, for a subagent. */
	parent?: string;
	/** The owner *user*, for anything below one. On a service it is the user
	 *  whose instance this is; absent means an org-level instance everyone
	 *  shares, which belongs to no one cluster. */
	owner?: string;
	/** Lossless hover text, where `label` is a shortened form of it — a user's
	 *  full email plus display name, which domain stripping throws away. */
	title?: string;
	/** Descendant count, for the tooltip. */
	sub?: number;
	/** Service instance status, for the tooltip. */
	status?: string;
	/** A service node invented from the event stream, with no listing behind
	 *  it. Its owner is unknown rather than absent, so it must not be reported
	 *  as org-wide. */
	unlisted?: boolean;
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
	/**
	 * Wire `service` value from an `action.*` event → node id.
	 *
	 * The event carries the caller-supplied *name* and nothing else, but a name
	 * is only unique per owner, so the answer depends on who called. This
	 * mirrors the gateway's own `resolve_service_instance_by_name`: the actor's
	 * own user-level instance shadows the org-level one of the same name.
	 *
	 * A name no listed instance matches — a user-level instance an admin can
	 * watch but not list — falls back to an unqualified id, which lands on the
	 * shared ring in no container rather than guessing at an owner.
	 */
	serviceIdFor(name: string | null | undefined, actorId?: string): string;
	/** How far from its owner an owned service's target sits, in world units.
	 *  The physics springs to the same length — a spring that disagrees with
	 *  the target leaves the instance between the two and stretches the
	 *  container out to reach it. Varies with how much of the tree is folded. */
	ownedServiceGap: number;
}

/** The aggregate node users collapse into. */
export const ORG_ID = 'agg:org';
/** Where a call that names no service lands. Mode A raw HTTP names the
 *  synthetic `http` pseudo-service, which *is* a real instance and gets a
 *  node of its own — this is only for a payload with no `service` at all. */
export const RAW_HTTP_ID = 'service:__none__';

/**
 * Node id for a listed service instance.
 *
 * Instance names are unique per `(org, owner)`, not per org — the map lists
 * with `include_user_level=true`, so an admin's payload can hold three rows
 * called `gcal` owned by three different users. Keying by name alone collapses
 * them onto one ball, and a ball can only sit inside one ownership container.
 * `org` stands in for an org-level instance, which has no owner.
 */
function serviceNodeIdFor(ownerUserId: string | undefined, name: string): string {
	return `service:${ownerUserId ?? 'org'}:${name}`;
}

/**
 * Node id for a name seen on the stream that no listed instance matched: an
 * org admin watching the whole org sees calls to user-level instances they
 * cannot themselves list. Two segments, so it never collides with a qualified
 * id, and `extraServiceIds` gives the traffic somewhere to land.
 */
function unlistedServiceNodeId(name: string): string {
	return `service:${name}`;
}

// Radii of the concentric rings, in world units. Lifted from the design's
// chosen values; the physics then relaxes everything off them.
const R_USER = 250;
const R_AGENT = 365;
const R_AGENT_COLLAPSED = 300;
const R_SUB_GAP = 85;
/** Shared service ring, per service. The ring has to clear the agents, but
 *  sizing it by a constant meant three services on a 700-unit circle set the
 *  fit radius and zoomed a small fleet down to something unreadable. Only
 *  org-level instances ride it now, so the count it is sized by is smaller. */
const R_SERVICE_MIN_GAP = 170;
const R_SERVICE_PER_NODE = 42;
/** How far past a user's outermost subagent that user's own services sit,
 *  measured from the user rather than from the centre. */
const R_OWNED_SERVICE_GAP = 40;
/** Angular spread between siblings, radians. Services fan wider than agents
 *  because their arc is further out and their balls are square. */
const SPREAD_AGENT = 0.42;
const SPREAD_SUB = 0.11;
const SPREAD_SERVICE = 0.5;

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
function identityNodes(identities: Identity[], allowedDomains: string[]): MapNode[] {
	const byId = new Map(identities.map((i) => [i.id, i]));
	const childCount = new Map<string, number>();
	for (const i of identities) {
		if (i.parent_id) childCount.set(i.parent_id, (childCount.get(i.parent_id) ?? 0) + 1);
	}

	return identities.map((i) => {
		// `$lib/identityDisplay` owns what an identity is called: a user's real
		// handle is their email, domain-stripped when the org has one sign-in
		// domain, and the IdP `name` claim is neither unique nor stable. The
		// container chip is named off this, so a cluster reads the same as its
		// row in the users list. Agents have no email and keep their name.
		const display = formatIdentity(i, allowedDomains);
		if (i.kind === 'user') {
			return {
				id: i.id,
				kind: 'user' as const,
				label: display.primary,
				mono: mono(display.primary),
				title: display.title,
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
			label: display.primary,
			mono: mono(display.primary),
			title: display.title,
			// Agents are created through the API and have no IdP, so this is
			// almost always undefined — but the column is on every identity,
			// so read it rather than assume.
			picture: i.picture ?? undefined,
			icon: i.icon_url ?? undefined,
			stripe: i.icon_stripe ?? undefined,
			parent: i.parent_id ?? undefined,
			owner,
			sub: childCount.get(i.id) ?? 0
		};
	});
}

/**
 * `owner_identity_id` → the *user* whose cluster owns it.
 *
 * The column can name an agent: an `on_behalf_of` create binds the instance to
 * the agent rather than to its user. Containers are keyed by user, so walk up
 * the tree the way `identityNodes` reads depth rather than the `kind` column.
 * An owner outside the returned set (archived, or filtered out) resolves to
 * itself — the instance is someone's, we just cannot name whose.
 */
function ownerUserResolver(identities: Identity[]): (id: string) => string {
	const byId = new Map(identities.map((i) => [i.id, i]));
	return (id: string): string => {
		const seen = new Set<string>();
		let cur = id;
		for (;;) {
			if (seen.has(cur)) return cur;
			seen.add(cur);
			const n = byId.get(cur);
			if (!n || n.kind === 'user') return cur;
			const next = n.owner_id ?? n.parent_id;
			if (!next) return cur;
			cur = next;
		}
	};
}

/** A listed instance with its owner resolved to a user and its node id minted
 *  once, so the nodes and the name→id index cannot disagree. */
interface ListedInstance {
	id: string;
	owner?: string;
	summary: ServiceInstanceSummary;
}

function listedInstances(
	services: ServiceInstanceSummary[],
	ownerUserOf: (id: string) => string
): ListedInstance[] {
	return services.map((s) => {
		const owner = s.owner_identity_id ? ownerUserOf(s.owner_identity_id) : undefined;
		return { id: serviceNodeIdFor(owner, s.name), owner, summary: s };
	});
}

function serviceNodes(listed: ListedInstance[], extraIds: string[]): MapNode[] {
	const nodes: MapNode[] = listed.map(({ id, owner, summary }) => ({
		id,
		kind: 'service' as const,
		label: summary.name,
		mono: mono(summary.name, 2),
		icon: summary.icon_url ?? undefined,
		owner,
		status: summary.status
	}));
	// Added only once traffic has actually used them — a permanent "raw http"
	// ball on the ring of an org that never makes one would be noise.
	const known = new Set(nodes.map((n) => n.id));
	// An instance first seen in traffic is keyed by bare name; the fleet
	// refetch that lists it mints a qualified id for the same instance. Drop
	// the unqualified one, or the map draws that service twice.
	const listedNames = new Set(listed.map((l) => l.summary.name));
	for (const id of extraIds) {
		if (known.has(id)) continue;
		const label = id === RAW_HTTP_ID ? 'direct' : id.slice('service:'.length);
		if (id !== RAW_HTTP_ID && listedNames.has(label)) continue;
		known.add(id);
		nodes.push({
			id,
			kind: 'service' as const,
			label,
			mono: mono(label, 2),
			unlisted: true,
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
	overrides: Record<string, boolean>,
	/** Org sign-in domains, so a user's label matches the users list. */
	allowedDomains: string[] = []
): Graph {
	const ownerUserOf = ownerUserResolver(identities);
	const listed = listedInstances(services, ownerUserOf);
	const idNodes = identityNodes(identities, allowedDomains);
	const svcNodes = serviceNodes(listed, extraServiceIds);
	const all = [...idNodes, ...svcNodes];

	// (owner, name) → node id, for the name-only ids the event stream carries.
	const instanceKey = (owner: string | undefined, name: string) => `${owner ?? 'org'}\u0000${name}`;
	const instanceIndex = new Map<string, string>(
		listed.map((l) => [instanceKey(l.owner, l.summary.name), l.id])
	);
	const serviceIdFor = (name: string | null | undefined, actorId?: string): string => {
		if (!name) return RAW_HTTP_ID;
		const ownerUser = actorId ? ownerUserOf(actorId) : undefined;
		const own = ownerUser ? instanceIndex.get(instanceKey(ownerUser, name)) : undefined;
		if (own) return own;
		return instanceIndex.get(instanceKey(undefined, name)) ?? unlistedServiceNodeId(name);
	};

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

	// A user-level instance sits on its owner's spoke, just past that user's
	// subagents, so the ownership container encloses it without stretching out
	// to the shared ring. Placed as an *offset from the owner*, not at an
	// absolute radius: the physics springs it to the owner, and a target the
	// spring cannot reach only stretches the box between the two.
	const agentOffset = collapse.users ? agentR : agentR - R_USER;
	// `ring` counts the pass that found no children, and starts at one, so the
	// number of subagent levels actually placed is two less. With the subagents
	// lane folded there is nothing on those rings to clear, and reserving the
	// space anyway leaves a band of empty box between a user and their
	// services. The shared ring below keeps its own (looser) reckoning — it
	// only has to clear the tree, whereas this has to land right next to it.
	const subLevels = collapse.subagents ? 0 : Math.max(0, ring - 2);
	const ownedOffset = agentOffset + R_SUB_GAP * subLevels + R_OWNED_SERVICE_GAP;
	const owned = svcNodes.filter((s) => s.owner);
	let ownedReach = 0;
	for (const u of users) {
		const own = owned.filter((s) => s.owner === u.id);
		// `userAngle` is populated even with users collapsed, so a folded org
		// still fans its services out by owner instead of piling them up.
		const base = collapse.users ? { x: 0, y: 0 } : targets.get(u.id) ?? { x: 0, y: 0 };
		own.forEach((s, j) => {
			const ang = (userAngle.get(u.id) ?? 0) + (j - (own.length - 1) / 2) * SPREAD_SERVICE;
			const off = polar(ownedOffset, ang);
			const t = { x: base.x + off.x, y: base.y + off.y };
			ownedReach = Math.max(ownedReach, Math.hypot(t.x, t.y));
			targets.set(s.id, t);
		});
	}
	// Whatever is left: org-level instances, plus anything owned by an identity
	// outside the returned set, which has no spoke to sit on. The ring has to
	// clear both the subagents and everyone's owned services.
	const shared = svcNodes.filter((s) => !targets.has(s.id));
	const svcR = Math.max(
		Math.max(agentR + R_SUB_GAP * Math.max(1, ring - 1), ownedReach) + R_SERVICE_MIN_GAP,
		shared.length * R_SERVICE_PER_NODE
	);
	shared.forEach((s, i) => {
		const n = shared.length;
		targets.set(s.id, polar(svcR, (i * 2 * Math.PI) / n + Math.PI / n));
	});

	const rootOf = new Map<string, string>();
	for (const n of structural) {
		if (n.kind === 'user' || n.kind === 'org') rootOf.set(n.id, n.id);
		else if (n.kind === 'agent') rootOf.set(n.id, n.owner ? resolve(n.owner) : n.id);
		else if (n.kind === 'subagent') rootOf.set(n.id, n.owner ? resolve(n.owner) : n.id);
		// A user-level instance is reachable only by its owner's fleet, so it
		// belongs in that cluster. Org-level instances get no entry: they are
		// called from several clusters and belong inside none of them.
		else if (n.kind === 'service' && n.owner) rootOf.set(n.id, resolve(n.owner));
	}

	return {
		byId,
		structural,
		structSet,
		edges,
		hidden,
		targets,
		rootOf,
		resolve,
		closedFor,
		serviceIdFor,
		ownedServiceGap: ownedOffset
	};
}
