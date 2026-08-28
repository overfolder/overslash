/**
 * The Live Map's simulation: force layout, canvas rendering, and the packets
 * that represent calls in flight.
 *
 * Deliberately free of Svelte. It writes `style.transform` on the DOM nodes
 * and repaints the canvas every animation frame — routing that through
 * reactive state would mean a re-render per frame of a list that has not
 * changed. The component owns *which* nodes exist; this owns where they are
 * and what is moving between them, and the only reactive traffic between the
 * two is `onShownChange`, which fires at most every 220ms.
 *
 * Ported from the `Live Map.html` design prototype, whose synthetic traffic
 * generator is replaced by `startCall`/`finishCall` driven off the `action.*`
 * event stream.
 */
import type { Graph, MapNode, NodeKind } from './graph';

/** Node diameters, px. Agents and subagents share a size — a subagent is
 *  marked by its dashed border, not by being smaller. */
export const SIZES = { user: 60, agent: 40, subagent: 40, service: 42 } as const;

/** Users are heavy anchors: agents swing around them, not the other way round. */
const MASS: Record<NodeKind, number> = { user: 10, org: 12, service: 6, agent: 1, subagent: 0.7 };

const SPRING_K = 14;
const SHELL_R = 118;
const USER_GAP = 460;
/** How long a node stays lit after its last call, before "Active only" hides it. */
const IDLE_GRACE_MS = 1000;

/** Edge crossings per second. Slow enough that a 40ms call is still visible —
 *  otherwise a busy fleet reads as an idle one. */
const FLIGHT_SPEED = 1.1;
/** A call whose `action.completed` never arrives — a dropped stream, a server
 *  restart mid-flight — must not park its packet forever. */
const HOLD_TIMEOUT_MS = 30_000;
/** Activity-derived service edges expire, so a one-off call doesn't pin an
 *  edge for the rest of the session. */
const SERVICE_EDGE_TTL_MS = 5 * 60_000;
/** Backstop. A packet whose endpoints never materialise is invisible but not
 *  free, and a busy fleet can out-produce the drain rate. */
const MAX_PACKETS = 400;

const MIN_ZOOM = 0.2;
const MAX_ZOOM = 1.6;

/** Container padding around a cluster's outermost balls, world units. The top
 *  is deeper than the sides because the name chip hangs off that edge. */
const BOX_PAD_X = 16;
const BOX_PAD_TOP = 26;
const BOX_PAD_BOTTOM = 22;
const BOX_RADIUS = 14;
/** How far in from the box's left edge the name chip sits. */
const CHIP_INSET = 10;
/** Gap left under the chip so it does not sit on the cluster's top row. */
const CHIP_CLEARANCE = 4;
/** Breathing room two containers insist on before they stop pushing apart. */
const BOX_GAP = 18;
const BOX_PUSH = 5;
/** Clearance a non-member keeps from a container it is not in. */
const STRAY_GAP = 10;
const STRAY_PUSH = 6;
/** How much of a stray's push the cluster it is intruding on takes back. */
const STRAY_REACTION = 0.25;
/** Clearance two nodes keep from each other, measured on what is drawn — the
 *  ball *and* its caption — rather than on the radii the springs reason about.
 *  A pair the layout considers comfortably apart can still have two labels
 *  lying across each other. */
const NODE_GAP = 8;
/** Penetration below this is not worth keeping the whole layout awake for. */
const SEPARATION_EPSILON = 4;
/** Overlap the positional pass tolerates, in world units, so the ring spring
 *  pulling back a fraction of a unit per frame is not corrected back out again
 *  forever. Under a pixel at any zoom the map offers. */
const SEPARATION_SLOP = 2;
/** Separating one pair can push a box into a third; a handful of passes settles
 *  the common cases without turning a frame into a solver. */
const SEPARATION_PASSES = 4;
/** Pointer slop, px, before a chip press counts as a drag rather than a click. */
const DRAG_SLOP = 3;

export type CallOutcome = 'called' | 'denied' | 'rejected' | 'failed' | 'upstream_error';

interface Vec {
	x: number;
	y: number;
	vx: number;
	vy: number;
}

interface Packet {
	callId: string;
	/** Unresolved node ids. The resolved pair is recomputed per frame, so a
	 *  packet keeps flying when its endpoints fold under a collapsed parent. */
	from: string;
	to: string;
	phase: 'req' | 'hold' | 'res';
	t: number;
	since: number;
	outcome?: CallOutcome;
	/** Set when `completed` arrived before the outbound leg finished. */
	pending?: CallOutcome;
	edge?: string;
}

/**
 * One ownership container: the dashed box drawn around a user's cluster, or —
 * once the cluster is folded — the chip standing in for it.
 *
 * `x0..y1` is the world-space box and is meaningless while `collapsed`; the
 * chip anchor `lx,ly` outlives it, so folding leaves the name where the box's
 * top-left corner was rather than teleporting it to the cluster's centre.
 */
interface Box {
	x0: number;
	y0: number;
	x1: number;
	y1: number;
	lx: number;
	ly: number;
	/** The root and its members, cached for the separation passes. */
	ids: string[];
	collapsed: boolean;
	/** No remembered anchor yet — the chip centres on the root instead. */
	centered: boolean;
	count: number;
	running: number;
	waiting: number;
}

/**
 * A rectangle in world units.
 *
 * Everything the positional passes separate reduces to one of these — a node
 * with the caption under it, a container, the chip a folded container leaves
 * behind — so one contact rule serves all three, and `Box` is one already.
 */
interface Rect {
	x0: number;
	y0: number;
	x1: number;
	y1: number;
}

/** One thing the shape pass can move: a whole cluster (open, or folded into
 *  its chip) or a single node that belongs to no open container. */
type Shape =
	| { cluster: true; root: string; b: Box; rect: Rect; held: boolean }
	| { cluster: false; id: string; rect: Rect; held: boolean };

/**
 * How far a pair of rectangles has to move to sit `gap` apart, and which way —
 * or `null` when the move is not worth making.
 *
 * The gap goes in before the test, so this acts on any pair closer than the
 * clearance rather than only on a pair already overlapping: two shapes touching
 * read no better than two overlapping, and it is the convention the forces use
 * too. `SEPARATION_SLOP` then applies to that shortfall — it is a floor on
 * movement worth making, not on overlap worth caring about.
 */
function contact(a: Rect, b: Rect, gap: number) {
	const needX = Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0) + gap;
	const needY = Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0) + gap;
	if (needX <= SEPARATION_SLOP || needY <= SEPARATION_SLOP) return null;
	// Out by the cheaper axis, the same choice the forces make.
	const alongX = needX < needY;
	const mag = alongX ? needX : needY;
	const aFirst = alongX
		? (a.x0 + a.x1) / 2 <= (b.x0 + b.x1) / 2
		: (a.y0 + a.y1) / 2 <= (b.y0 + b.y1) / 2;
	const dir = aFirst ? -1 : 1;
	// The direction `a` moves in. `b` moves the other way.
	return { ux: alongX ? dir : 0, uy: alongX ? 0 : dir, mag };
}

/** Slide a rectangle with what it describes, so the rest of the pass tests
 *  against where things now are rather than where they started. */
function shift(r: Rect, dx: number, dy: number) {
	r.x0 += dx;
	r.x1 += dx;
	r.y0 += dy;
	r.y1 += dy;
}

export interface TooltipCall {
	label: string;
	waiting: boolean;
}

export interface SimCallbacks {
	/** Node ids that should have DOM nodes now — includes those mid-fade-out. */
	onShownChange(ids: string[]): void;
	onZoomChange(percent: number): void;
}

export interface SimMounts {
	stage: HTMLElement;
	canvas: HTMLCanvasElement;
	layer: HTMLElement;
	/** Holds the container name chips. Panned and zoomed with the map, but each
	 *  chip counter-scales so its text stays screen-constant. */
	chipLayer: HTMLElement;
}

export function createSim(mounts: SimMounts, cb: SimCallbacks) {
	const { stage, canvas, layer, chipLayer } = mounts;

	let graph: Graph | null = null;
	let hits: Set<string> | null = null;
	let hideIdle = true;

	const pos = new Map<string, Vec>();
	const target = new Map<string, { x: number; y: number }>();
	const nodeEls = new Map<string, HTMLElement>();
	const lastActive = new Map<string, number>();
	const waiting = new Set<string>();
	const seenAt = new Map<string, number>();
	const leaving = new Map<string, number>();
	let prevLive = new Set<string>();

	/** Cluster root → folded. Owned by the component; pushed in wholesale. */
	let boxClosed: Record<string, boolean> = {};
	const boxes = new Map<string, Box>();
	const chipEls = new Map<string, HTMLElement>();
	/** Chip size in *screen* pixels, measured at the UI cadence rather than per
	 *  frame: reading `offsetWidth` right after writing transforms forces a
	 *  synchronous layout, and the value only changes when the label does. */
	const chipPx = new Map<string, { w: number; h: number }>();
	/** A node's rendered extent in world units, as offsets from its anchor.
	 *  A ball is only part of a node: the caption under it is a DOM element with
	 *  its own width and its own `scale()`, and it is the wider of the two, so
	 *  `radiusOf` describes a circle the node routinely sticks out of. Measured
	 *  on the same cadence and for the same reason as `chipPx`; unlike a chip
	 *  this rides the map's zoom, so the world offsets hold at any `k`. */
	const nodeExtent = new Map<string, { dx0: number; dx1: number; dy0: number; dy1: number }>();
	/** Where each container's chip sat the last time its box was drawn open. */
	const lastChipAnchor = new Map<string, { x: number; y: number }>();
	/** Targets a human placed by hand. `setGraph` must not re-seed these, or a
	 *  cluster someone dragged aside snaps back on the next fleet refetch. */
	const manualTargets = new Set<string>();

	const packets: Packet[] = [];
	const byCall = new Map<string, Packet>();
	/** `${from}>${to}` in *unresolved* ids → when a call last used it. */
	const serviceEdges = new Map<string, { from: string; to: string; seen: number }>();

	const view = { k: 0.75, tx: stage.clientWidth / 2, ty: stage.clientHeight / 2 };
	let pin: { id: string; dragging: boolean; released?: number; since: number } | null = null;
	let drag:
		| { mode: 'pan'; sx: number; sy: number; tx: number; ty: number }
		| { mode: 'node'; id: string; sx: number; sy: number; ox: number; oy: number }
		| null = null;
	let groupDrag: {
		root: string;
		ids: string[];
		wx: number;
		wy: number;
		sx: number;
		sy: number;
		moved: boolean;
		orig: { x: number; y: number }[];
	} | null = null;
	/** Set when a chip press turned into a real drag, so the button's click —
	 *  which fires anyway — does not also toggle the container. */
	let groupDragMoved = false;
	let alpha = { v: 1, n: -1 };
	let hoverId: string | null = null;

	let colors = {
		primary: '#6359d9',
		success: '#21b86b',
		danger: '#e53836',
		warning: '#d97706',
		edge: '#e8e8ee',
		tree: '#111213'
	};

	function readColors() {
		const cs = getComputedStyle(document.documentElement);
		const g = (n: string, fallback: string) => cs.getPropertyValue(n).trim() || fallback;
		colors = {
			primary: g('--color-primary', colors.primary),
			success: g('--color-success', colors.success),
			danger: g('--color-danger', colors.danger),
			warning: g('--color-warning', colors.warning),
			edge: g('--color-border', colors.edge),
			tree: g('--color-text-heading', colors.tree)
		};
	}
	readColors();
	// The canvas can't inherit a CSS variable, so a theme flip has to be
	// pushed into these by hand.
	const themeObserver = new MutationObserver(readColors);
	themeObserver.observe(document.documentElement, {
		attributes: true,
		attributeFilter: ['data-theme']
	});

	const meta = (id: string) => graph?.byId.get(id);
	const radiusOf = (id: string) => {
		const k = meta(id)?.kind;
		if (!k) return 18;
		if (k === 'org') return (SIZES.user * 1.24) / 2;
		return SIZES[k] / 2;
	};
	const resolve = (id: string) => graph?.resolve(id) ?? id;

	// ── graph + filters ──────────────────────────────────────────────────
	function setGraph(next: Graph) {
		graph = next;
		for (const [id, t] of next.targets) {
			// A pinned node keeps the position the user gave it; re-seeding
			// from the layout would yank it back mid-gesture. Same for a
			// cluster dragged by its chip: that gesture has to outlive the
			// fleet refetch that rebuilt the graph.
			if (pin?.id === id || manualTargets.has(id)) continue;
			target.set(id, t);
			if (!pos.has(id)) pos.set(id, { x: t.x, y: t.y, vx: 0, vy: 0 });
		}
		alpha = { v: 1, n: -1 };
	}
	const setHits = (next: Set<string> | null) => {
		hits = next;
	};
	const setHideIdle = (v: boolean) => {
		hideIdle = v;
	};
	const setBoxClosed = (v: Record<string, boolean>) => {
		boxClosed = v;
		// A fold changes who is on screen; wake the layout so the boxes that
		// remain redraw at their new extent instead of on the next call.
		alpha.v = Math.max(alpha.v, 0.5);
	};

	function registerNode(id: string, el: HTMLElement | null) {
		if (el) nodeEls.set(id, el);
		else {
			nodeEls.delete(id);
			nodeExtent.delete(id);
		}
	}

	function registerChip(root: string, el: HTMLElement | null) {
		if (el) chipEls.set(root, el);
		else {
			chipEls.delete(root);
			chipPx.delete(root);
		}
	}

	/** Everything under a cluster root, excluding the root itself. */
	function memberIds(root: string): string[] {
		if (!graph) return [];
		const out: string[] = [];
		for (const n of graph.structural) {
			if (n.id !== root && graph.rootOf.get(n.id) === root) out.push(n.id);
		}
		return out;
	}

	/**
	 * Is this node folded away inside a collapsed container?
	 *
	 * A user-level service has a `rootOf` entry like an agent does, so it folds
	 * with its owner's cluster for free. Org-level ones have none — they sit on
	 * the shared outer ring, in no container — and fall out of this the same way.
	 */
	function inClosedBox(n: MapNode): boolean {
		if (n.kind === 'user' || n.kind === 'org') return !!boxClosed[n.id];
		const root = graph?.rootOf.get(n.id);
		return !!root && root !== n.id && !!boxClosed[root];
	}

	const isBoxHidden = (id: string) => {
		const n = meta(id);
		return !!n && inClosedBox(n);
	};

	// ── traffic ──────────────────────────────────────────────────────────
	function touch(id: string, now = performance.now()) {
		lastActive.set(id, now);
		const n = meta(id);
		if (n?.parent) lastActive.set(n.parent, now);
		if (n?.owner) lastActive.set(n.owner, now);
	}

	function ensureServiceEdge(from: string, to: string) {
		serviceEdges.set(`${from}>${to}`, { from, to, seen: performance.now() });
	}

	// Neither of these checks that the endpoints exist yet. The node for a
	// service seen for the first time, or for an agent created since the page
	// loaded, arrives a tick later; the draw pass simply skips a packet it
	// cannot place, and picks it up once it can.
	function startCall(callId: string, from: string, to: string) {
		if (byCall.has(callId)) return;
		if (packets.length >= MAX_PACKETS) {
			const dropped = packets.shift();
			if (dropped) byCall.delete(dropped.callId);
		}
		const p: Packet = { callId, from, to, phase: 'req', t: 0, since: performance.now() };
		packets.push(p);
		byCall.set(callId, p);
		ensureServiceEdge(from, to);
		touch(from);
		// Wake the layout: a node that was hidden as idle is about to appear.
		alpha.v = Math.max(alpha.v, 0.5);
	}

	/**
	 * `action.completed`. The two events are not ordered, so this also has to
	 * cope with never having seen the `called` — it spawns a packet already on
	 * its return leg rather than dropping the call from the map entirely.
	 */
	function finishCall(callId: string, from: string, to: string, outcome: CallOutcome) {
		const existing = byCall.get(callId);
		if (!existing) {
			const p: Packet = { callId, from, to, phase: 'res', t: 1, since: performance.now(), outcome };
			packets.push(p);
			byCall.set(callId, p);
			ensureServiceEdge(from, to);
			touch(from);
			return;
		}
		if (existing.phase === 'req') existing.pending = outcome;
		else if (existing.phase === 'hold') {
			existing.phase = 'res';
			existing.outcome = outcome;
		}
	}

	/** Approval state for one identity, from `approval.pending`/`.resolved`. */
	function setWaiting(identityId: string, isWaiting: boolean) {
		if (isWaiting) {
			waiting.add(identityId);
			touch(identityId);
		} else {
			waiting.delete(identityId);
		}
	}

	/** After `stream.resync`: anything in flight may have finished unseen. */
	function clearTraffic() {
		packets.length = 0;
		byCall.clear();
		serviceEdges.clear();
		waiting.clear();
		lastActive.clear();
	}

	// ── view ─────────────────────────────────────────────────────────────
	function zoomBy(f: number) {
		const mx = stage.clientWidth / 2;
		const my = stage.clientHeight / 2;
		const nk = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, view.k * f));
		view.tx = mx - (mx - view.tx) * (nk / view.k);
		view.ty = my - (my - view.ty) * (nk / view.k);
		view.k = nk;
	}

	function fitView() {
		if (!graph) return;
		let R = 0;
		for (const t of graph.targets.values()) R = Math.max(R, Math.hypot(t.x, t.y));
		if (R === 0) R = 1;
		const pad = 74;
		view.k = Math.min(
			1.1,
			Math.max(
				0.3,
				Math.min(
					(stage.clientWidth - pad * 2) / (R * 2),
					(stage.clientHeight - pad * 2) / (R * 2)
				)
			)
		);
		view.tx = stage.clientWidth / 2;
		view.ty = stage.clientHeight / 2;
	}

	function recenter() {
		pin = null;
		manualTargets.clear();
		if (graph) for (const [id, t] of graph.targets) target.set(id, t);
		fitView();
		alpha.v = 1;
	}

	// ── pointer ──────────────────────────────────────────────────────────
	const isOverlay = (e: Event) =>
		e.target instanceof Element &&
		!!(
			e.target.closest('.lm-node-in') ||
			e.target.closest('.lm-panel') ||
			e.target.closest('.lm-boxchip')
		);

	const toWorld = (clientX: number, clientY: number): [number, number] => {
		const r = stage.getBoundingClientRect();
		return [(clientX - r.left - view.tx) / view.k, (clientY - r.top - view.ty) / view.k];
	};

	function onStagePointerDown(e: PointerEvent) {
		if (isOverlay(e)) return;
		drag = { mode: 'pan', sx: e.clientX, sy: e.clientY, tx: view.tx, ty: view.ty };
		stage.classList.add('is-panning');
		stage.setPointerCapture(e.pointerId);
	}

	function onNodePointerDown(e: PointerEvent, id: string) {
		e.stopPropagation();
		if (pin && pin.id !== id) pin = null;
		const p = pos.get(id);
		if (!p) return;
		drag = { mode: 'node', id, sx: e.clientX, sy: e.clientY, ox: p.x, oy: p.y };
		stage.setPointerCapture(e.pointerId);
	}

	/**
	 * Grab a container by its chip. The whole cluster moves as one — dragging a
	 * single member out would only deform the box it is drawn from.
	 */
	function onChipPointerDown(e: PointerEvent, root: string) {
		e.stopPropagation();
		const ids = [root, ...memberIds(root)];
		groupDragMoved = false;
		const [wx, wy] = toWorld(e.clientX, e.clientY);
		groupDrag = {
			root,
			ids,
			wx,
			wy,
			sx: e.clientX,
			sy: e.clientY,
			moved: false,
			orig: ids.map((id) => {
				const p = pos.get(id);
				return { x: p?.x ?? 0, y: p?.y ?? 0 };
			})
		};
		// Capture on the chip, not the stage. A capture retargets the
		// compatibility mouse events too, and `click` is dispatched at the
		// common ancestor of mousedown and mouseup — capture the stage and that
		// ancestor is the stage, so the button's own click never fires and the
		// container can never be folded. Pointer events still bubble from the
		// chip to the stage, so the drag handlers below keep working.
		chipEls.get(root)?.setPointerCapture(e.pointerId);
		stage.classList.add('is-grabbing-group');
	}

	/**
	 * Did the last chip press turn into a drag? Reading it clears it, so the
	 * click that trails a drag is swallowed and the next one is not.
	 */
	function consumeGroupDrag(): boolean {
		const moved = groupDragMoved;
		groupDragMoved = false;
		return moved;
	}

	function onPointerMove(e: PointerEvent) {
		const g = groupDrag;
		if (g) {
			if (!g.moved) {
				// Below the slop threshold this is still a click, and moving the
				// cluster by two pixels under the cursor would make every fold
				// feel like a failed drag.
				if (Math.abs(e.clientX - g.sx) <= DRAG_SLOP && Math.abs(e.clientY - g.sy) <= DRAG_SLOP)
					return;
				g.moved = true;
			}
			const [wx, wy] = toWorld(e.clientX, e.clientY);
			const dx = wx - g.wx;
			const dy = wy - g.wy;
			g.ids.forEach((id, i) => {
				const p = pos.get(id);
				if (!p) return;
				p.x = g.orig[i].x + dx;
				p.y = g.orig[i].y + dy;
				p.vx = 0;
				p.vy = 0;
				// Move the target too, or the springs drag the cluster home the
				// moment the pointer lifts.
				target.set(id, { x: p.x, y: p.y });
				manualTargets.add(id);
			});
			alpha.v = 1;
			return;
		}
		if (!drag) return;
		if (drag.mode === 'pan') {
			view.tx = drag.tx + (e.clientX - drag.sx);
			view.ty = drag.ty + (e.clientY - drag.sy);
			return;
		}
		const p = pos.get(drag.id);
		if (!p) return;
		p.x = drag.ox + (e.clientX - drag.sx) / view.k;
		p.y = drag.oy + (e.clientY - drag.sy) / view.k;
		target.set(drag.id, { x: p.x, y: p.y });
		if (pin?.id !== drag.id) pin = { id: drag.id, dragging: true, since: performance.now() };
	}

	function onPointerUp() {
		if (groupDrag) {
			groupDragMoved = groupDrag.moved;
			groupDrag = null;
			stage.classList.remove('is-grabbing-group');
		}
		if (pin?.dragging) {
			pin.dragging = false;
			pin.released = performance.now();
		}
		drag = null;
		stage.classList.remove('is-panning');
	}

	function onWheel(e: WheelEvent) {
		e.preventDefault();
		if (e.ctrlKey || e.metaKey) {
			const r = stage.getBoundingClientRect();
			const mx = e.clientX - r.left;
			const my = e.clientY - r.top;
			const nk = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, view.k * (1 - e.deltaY * 0.0016)));
			view.tx = mx - (mx - view.tx) * (nk / view.k);
			view.ty = my - (my - view.ty) * (nk / view.k);
			view.k = nk;
		} else {
			view.tx -= e.deltaX;
			view.ty -= e.deltaY;
		}
	}
	stage.addEventListener('wheel', onWheel, { passive: false });

	const setHover = (id: string | null) => {
		hoverId = id;
	};

	// ── frame ────────────────────────────────────────────────────────────
	let raf = 0;
	let last = performance.now();
	let uiAcc = 0;

	function advancePackets(dt: number, now: number) {
		for (let i = packets.length - 1; i >= 0; i--) {
			const c = packets[i];
			if (c.phase === 'req') {
				c.t += FLIGHT_SPEED * dt;
				if (c.t >= 1) {
					c.t = 1;
					if (c.pending) {
						c.phase = 'res';
						c.outcome = c.pending;
					} else {
						c.phase = 'hold';
						c.since = now;
					}
				}
			} else if (c.phase === 'hold') {
				if (now - c.since > HOLD_TIMEOUT_MS) {
					packets.splice(i, 1);
					byCall.delete(c.callId);
					continue;
				}
			} else {
				c.t -= FLIGHT_SPEED * 1.3 * dt;
				if (c.t <= 0) {
					packets.splice(i, 1);
					byCall.delete(c.callId);
					continue;
				}
			}
			touch(c.from, now);
		}
		for (const [key, e] of serviceEdges) {
			if (now - e.seen > SERVICE_EDGE_TTL_MS) serviceEdges.delete(key);
		}
	}

	/** Tree edges, plus whatever service edges traffic has revealed. */
	function activeEdges(): { id: string; from: string; to: string; tree: boolean }[] {
		if (!graph) return [];
		const out = graph.edges.map((e) => ({ ...e, tree: true }));
		const seen = new Set(out.map((e) => e.id));
		for (const e of serviceEdges.values()) {
			const a = resolve(e.from);
			const b = resolve(e.to);
			if (a === b) continue;
			const id = `${a}>${b}`;
			if (seen.has(id)) continue;
			seen.add(id);
			out.push({ id, from: a, to: b, tree: false });
		}
		return out;
	}

	function frame(now: number) {
		const dt = Math.min(0.045, (now - last) / 1000);
		last = now;
		if (!graph) {
			raf = requestAnimationFrame(frame);
			return;
		}

		advancePackets(dt, now);
		const edges = activeEdges();

		const edgeBusy = new Set<string>();
		const nodeState = new Map<string, 'running' | 'waiting'>();
		for (const c of packets) {
			const a = resolve(c.from);
			const b = resolve(c.to);
			if (a === b) {
				c.edge = undefined;
				continue;
			}
			c.edge = `${a}>${b}`;
			edgeBusy.add(c.edge);
			for (const n of [a, b]) nodeState.set(n, 'running');
		}
		// Waiting outranks running: an agent with one gated call and five live
		// ones is, for the operator reading the map, blocked.
		for (const id of waiting) nodeState.set(resolve(id), 'waiting');

		const live = new Set<string>();
		for (const n of graph.structural) {
			// Folded into a collapsed container: off the map entirely, however
			// busy it is. Its chip reports the activity instead.
			if (inClosedBox(n)) continue;
			const busy = (lastActive.get(n.id) ?? 0) > now - IDLE_GRACE_MS || nodeState.has(n.id);
			const keep =
				!hideIdle ||
				n.kind === 'user' ||
				n.kind === 'org' ||
				n.kind === 'service' ||
				busy ||
				pin?.id === n.id ||
				hits?.has(n.id) ||
				hoverId === n.id;
			if (keep) live.add(n.id);
		}

		// Enter/leave fades. Edges and packets follow the same curve as the DOM
		// nodes, so nothing is left drawn against a ball that has already gone.
		for (const id of live) {
			if (leaving.has(id)) {
				leaving.delete(id);
				nodeEls.get(id)?.classList.remove('is-leaving');
			}
			if (!seenAt.has(id)) seenAt.set(id, now);
		}
		for (const id of prevLive) {
			if (!live.has(id) && !leaving.has(id)) {
				leaving.set(id, now);
				seenAt.delete(id);
				nodeEls.get(id)?.classList.add('is-leaving');
			}
		}
		prevLive = live;
		const fadeOf = (id: string) => {
			// A fold is instant, not a fade: the component drops the ball on the
			// same tick, and an edge still drawn to where it was reads as a line
			// into nowhere.
			if (isBoxHidden(id)) return 0;
			const l = leaving.get(id);
			if (l != null) return Math.max(0, 1 - (now - l) / 360);
			const t0 = seenAt.get(id);
			return t0 == null ? 0 : Math.min(1, (now - t0) / 110);
		};

		// Forces first, then the two positional passes that have the last word.
		// Order is the whole point: `separateNodes` moves individual balls, so it
		// has to run *before* the boxes are built or `draw` strokes an outline
		// that no longer hugs its members; `separateShapes` moves whole clusters
		// and keeps their rectangles in step as it goes. `simulate` reads the
		// previous frame's boxes for its own push — which is fine, since they are
		// the corrected ones.
		simulate(dt, now, edges, live);
		separateNodes(live);
		computeBoxes(now, live);
		separateShapes(live);
		draw(now, edges, edgeBusy, fadeOf, live);

		uiAcc += dt;
		if (uiAcc > 0.22) {
			uiAcc = 0;
			for (const [id, el] of nodeEls) {
				el.classList.toggle('is-running', nodeState.get(id) === 'running');
				el.classList.toggle('is-waiting', nodeState.get(id) === 'waiting');
			}
			syncChips();
			measureNodes();
			for (const [id, t] of leaving) if (now - t > 400) leaving.delete(id);
			cb.onShownChange([...live, ...[...leaving.keys()].filter((i) => !live.has(i))]);
			cb.onZoomChange(Math.round(view.k * 100));
		}

		raf = requestAnimationFrame(frame);
	}

	/** Move a whole cluster as one. Mass-scaled, so every member gets the same
	 *  acceleration once the integrator divides mass back out — a flat force
	 *  would shear the light nodes off the heavy ones it is meant to carry. */
	function pushCluster(
		acc: Map<string, [number, number]>,
		ids: string[],
		fx: number,
		fy: number
	) {
		for (const id of ids) {
			const a = acc.get(id);
			if (!a) continue;
			const mass = MASS[meta(id)?.kind ?? 'agent'] ?? 1;
			a[0] += fx * mass;
			a[1] += fy * mass;
		}
	}

	// ── physics ──────────────────────────────────────────────────────────
	function simulate(
		dt: number,
		now: number,
		edges: { from: string; to: string; tree: boolean }[],
		live: Set<string>
	) {
		if (!graph) return;
		// Runs over the whole structure, not just the visible set: a hidden
		// idle agent still takes up space, so revealing it doesn't shove its
		// siblings across the screen.
		const ids = graph.structural.map((n) => n.id);
		const acc = new Map<string, [number, number]>();
		for (const id of ids) {
			acc.set(id, [0, 0]);
			if (!pos.has(id)) {
				const t = target.get(id) ?? { x: 0, y: 0 };
				pos.set(id, { x: t.x, y: t.y, vx: 0, vy: 0 });
			}
		}

		// An owned service is held by its user, not by a ring: the container is
		// drawn around whatever the layout produces, so the instance has to be
		// pulled towards the cluster rather than parked outside it.
		for (const id of ids) {
			const m = meta(id);
			if (m?.kind !== 'service' || !m.owner) continue;
			const root = resolve(m.owner);
			const a = pos.get(root);
			const b = pos.get(id);
			const fa = acc.get(root);
			const fb = acc.get(id);
			if (!a || !b || !fa || !fb) continue;
			// The layout's own offset, not a constant: spring and target have to
			// agree, or the instance settles between them and the box is
			// stretched to reach it. `graph.ownedServiceGap` shrinks when the
			// subagent rings fold away, and this has to shrink with it.
			let dx = b.x - a.x;
			let dy = b.y - a.y;
			const d = Math.hypot(dx, dy) || 1;
			// Never closer than the two of them can be drawn, and never pulling
			// back against a correction: see `clearance` and `restLength`.
			const L = Math.max(
				restLength(root, id, graph.ownedServiceGap),
				clearance(root, id, dx / d, dy / d)
			);
			const f = (d - L) * SPRING_K * 0.55;
			dx /= d;
			dy /= d;
			fa[0] += dx * f;
			fa[1] += dy * f;
			fb[0] -= dx * f;
			fb[1] -= dy * f;
		}

		for (const id of ids) {
			const p = pos.get(id);
			const m = meta(id);
			const t = target.get(id);
			const a = acc.get(id);
			if (!p || !m || !t || !a) continue;
			const mass = MASS[m.kind] ?? 1;
			if (pin?.id === id) {
				p.x = t.x;
				p.y = t.y;
				p.vx = 0;
				p.vy = 0;
				continue;
			}
			// Org services and users hold their ring; agents are free to swing.
			// An owned service is held loosely instead, because the spring to its
			// owner above is what places it: the two agree on the distance, so
			// the target is left to say only which *direction* from the owner.
			if (m.kind === 'service') {
				const w = m.owner ? 1.2 : 3;
				a[0] += (t.x - p.x) * w * mass;
				a[1] += (t.y - p.y) * w * mass;
			} else if (m.kind === 'user' || m.kind === 'org') {
				a[0] += (t.x - p.x) * 0.5 * mass;
				a[1] += (t.y - p.y) * 0.5 * mass;
			}
		}

		for (const e of edges) {
			const fa = acc.get(e.from);
			const fb = acc.get(e.to);
			const a = pos.get(e.from);
			const b = pos.get(e.to);
			const src = meta(e.from);
			if (!fa || !fb || !a || !b || !src) continue;
			const k = e.tree ? SPRING_K : SPRING_K * 0.024;
			let dx = b.x - a.x;
			let dy = b.y - a.y;
			const d = Math.hypot(dx, dy) || 1;
			// A tree edge holds its pair at a set distance, so that distance has
			// to be one they can be drawn at: see `clearance`. The loose edges
			// between a caller and a service hold nothing — they are a hint at
			// 340 units and a fortieth of the stiffness — and need no floor.
			const L = e.tree
				? Math.max(
						restLength(
							e.from,
							e.to,
							src.kind === 'user' || src.kind === 'org' ? SHELL_R : SHELL_R * 0.66
						),
						clearance(e.from, e.to, dx / d, dy / d)
					)
				: 340;
			const f = (d - L) * k;
			dx /= d;
			dy /= d;
			fa[0] += dx * f;
			fa[1] += dy * f;
			fb[0] -= dx * f;
			fb[1] -= dy * f;
		}

		// How far each node reaches from its anchor, so the pair loop below can
		// rule a pair out on a comparison rather than on a `clearance` call.
		const reach = ids.map((id) => {
			const e = extentOf(id);
			return Math.max(-e.dx0, e.dx1, -e.dy0, e.dy1);
		});
		for (let i = 0; i < ids.length; i++) {
			const ia = ids[i];
			const ma = meta(ia);
			const a = pos.get(ia);
			const fa = acc.get(ia);
			if (!ma || !a || !fa) continue;
			for (let j = i + 1; j < ids.length; j++) {
				const ib = ids[j];
				const mb = meta(ib);
				const b = pos.get(ib);
				const fb = acc.get(ib);
				if (!mb || !b || !fb) continue;
				const bothUsers =
					(ma.kind === 'user' || ma.kind === 'org') && (mb.kind === 'user' || mb.kind === 'org');
				const rootA = graph.rootOf.get(ia);
				const sameTree = !!rootA && rootA === graph.rootOf.get(ib);
				const pad = radiusOf(ia) + radiusOf(ib);
				const spacing = bothUsers
					? USER_GAP
					: sameTree
						? Math.max(56, pad + 18)
						: Math.max(112, pad + 60);
				let dx = b.x - a.x;
				let dy = b.y - a.y;
				let d2 = dx * dx + dy * dy;
				// Neither the layout's spacing nor anything `clearance` could ask
				// for reaches this far, so the pair is not each other's business.
				const bound = Math.max(spacing, reach[i] + reach[j] + NODE_GAP);
				if (d2 > bound * bound) continue;
				if (d2 === 0) {
					// Exactly coincident: no separating direction exists.
					// Nudge deterministically rather than dividing by zero.
					dx = i % 2 === 0 ? 0.5 : -0.5;
					dy = 0.5;
					d2 = 0.5;
				}
				const d = Math.sqrt(d2);
				// The layout's own spacing, floored by what the pair is actually
				// drawn as. A force content to leave them closer than they can be
				// drawn leaves `separateNodes` doing all of it and arguing with
				// whatever holds them — the ring spring wins the radial half of
				// that argument every frame, and the map never settles. With the
				// floor in, the force wants what the pass enforces, and by the
				// time the pass runs there is nothing left to correct.
				const min = Math.max(spacing, clearance(ia, ib, dx / d, dy / d));
				if (d >= min) continue;
				const f = ((min - d) * (bothUsers ? 3.2 : sameTree ? 5 : 7)) / d;
				fa[0] -= dx * f;
				fa[1] -= dy * f;
				fb[0] += dx * f;
				fb[1] += dy * f;
			}
		}

		// Containers must not overlap, or two boxes read as one shape and their
		// chips land on top of each other. Push whole clusters: nudging a single
		// member out only deforms the box it is drawn from.
		const openBoxes: Box[] = [];
		for (const b of boxes.values()) if (!b.collapsed) openBoxes.push(b);
		/** Worst unresolved overlap this frame, in world units. */
		let separation = 0;
		for (let i = 0; i < openBoxes.length; i++) {
			for (let j = i + 1; j < openBoxes.length; j++) {
				const A = openBoxes[i];
				const B = openBoxes[j];
				const ox = Math.min(A.x1, B.x1) - Math.max(A.x0, B.x0) + BOX_GAP;
				const oy = Math.min(A.y1, B.y1) - Math.max(A.y0, B.y0) + BOX_GAP;
				if (ox <= 0 || oy <= 0) continue;
				// Separate along whichever axis is cheaper to clear.
				let nx = 0;
				let ny = 0;
				let mag: number;
				if (ox < oy) {
					nx = (A.x0 + A.x1) / 2 <= (B.x0 + B.x1) / 2 ? -1 : 1;
					mag = ox;
				} else {
					ny = (A.y0 + A.y1) / 2 <= (B.y0 + B.y1) / 2 ? -1 : 1;
					mag = oy;
				}
				const f = mag * BOX_PUSH;
				// Scaled by mass, because the integrator divides it back out. A
				// flat force accelerates a mass-1 agent ten times harder than the
				// mass-10 user it orbits, which pulls the cluster apart instead of
				// moving it — the opposite of what pushing whole clusters is for.
				pushCluster(acc, A.ids, nx * f, ny * f);
				pushCluster(acc, B.ids, -nx * f, -ny * f);
				separation = Math.max(separation, mag - BOX_GAP);
			}
		}

		// Nothing that is not a member may sit inside a container. The box is a
		// claim about who belongs to whom, and a ball parked inside one reads as
		// membership — the more so since a service can now legitimately be a
		// member, so "it is in the box" is no longer obviously false for one.
		//
		// The stray takes the push and the cluster takes a quarter of it back.
		// All of it on the stray and a node held hard to its ring target would
		// sit there shoving forever; all of it on the cluster and one loose ball
		// could walk a whole fleet across the map.
		//
		// Only a node that is visible and belongs to no open container can be a
		// stray. A member of another cluster intruding here means the two boxes
		// intersect, which the pair loop above already says — and says it by
		// moving both clusters whole, rather than shearing one member out of the
		// fleet it is drawn with. A node hidden inside a folded container is not
		// on the map at all, and an invisible ball must not shove a visible box.
		const boxed = new Set<string>();
		for (const b of openBoxes) for (const id of b.ids) boxed.add(id);
		for (const b of openBoxes) {
			for (const id of ids) {
				if (boxed.has(id) || !live.has(id) || pin?.id === id) continue;
				const p = pos.get(id);
				const a = acc.get(id);
				if (!p || !a) continue;
				const e = nodeExtent.get(id);
				const r = radiusOf(id);
				// The caption counts: a label lying across a container's edge is
				// the same visual claim as the ball would be.
				const nx0 = p.x + (e ? e.dx0 : -r) - STRAY_GAP;
				const nx1 = p.x + (e ? e.dx1 : r) + STRAY_GAP;
				const ny0 = p.y + (e ? e.dy0 : -r) - STRAY_GAP;
				const ny1 = p.y + (e ? e.dy1 : r) + STRAY_GAP;
				if (nx1 <= b.x0 || nx0 >= b.x1 || ny1 <= b.y0 || ny0 >= b.y1) continue;
				// Leave by the nearest edge — the shortest way out is the one that
				// disturbs the layout least.
				// How far the *inflated* rect has to move to clear the box, which
				// is the distance still needed to reach the clearance: zero when
				// the stray is already `STRAY_GAP` away (the guard above skips
				// that case outright), `STRAY_GAP` when it is touching the box
				// with nothing overlapping, more when it is genuinely inside.
				const exits = [nx1 - b.x0, b.x1 - nx0, ny1 - b.y0, b.y1 - ny0];
				const m = Math.min(...exits);
				const ux = m === exits[0] ? -1 : m === exits[1] ? 1 : 0;
				const uy = ux !== 0 ? 0 : m === exits[2] ? -1 : 1;
				const f = m * STRAY_PUSH;
				const mass = MASS[meta(id)?.kind ?? 'agent'] ?? 1;
				a[0] += ux * f * mass;
				a[1] += uy * f * mass;
				// A flat share, not one divided among the members: `pushCluster`
				// already mass-scales, so `share` is an acceleration, and dividing
				// it by the member count would make a cluster progressively more
				// immovable the bigger it got. Big clusters are the ones with big
				// boxes, so that is exactly where the reaction is needed — it is
				// what breaks the deadlock when both the stray and the cluster are
				// held by their own ring targets.
				const share = f * STRAY_REACTION;
				pushCluster(acc, b.ids, -ux * share, -uy * share);
				// Penetration, which is a different question from the one the
				// force asks. Taking the gap back off `m` turns it into how far
				// the stray is actually *inside* the box — zero when it is merely
				// touching. `separation` only drives the cooling override, and a
				// stray sitting against a container is a resolved state: report it
				// as unresolved and the layout never cools again. Same convention
				// as the box pair above, which reports `mag - BOX_GAP`.
				separation = Math.max(separation, m - STRAY_GAP);
			}
		}

		// A separation force that the cooling has already frozen out is no force
		// at all: `sp < 5 && am < 30` locks a node in place, and at the alpha
		// floor an overlap of a few tens of units cannot clear that bar. Keep the
		// layout awake while anything is still overlapping, and let it settle the
		// moment nothing is.
		if (separation > SEPARATION_EPSILON) alpha.v = Math.max(alpha.v, 0.35);

		// Cooling: forces ease off as the layout settles and slow nodes freeze
		// outright. Without it the graph never stops shimmering.
		const damp = Math.pow(0.72, dt * 60);
		if (ids.length !== alpha.n) alpha = { v: 1, n: ids.length };
		if (drag?.mode === 'node') alpha.v = 1;
		const A = alpha.v;
		alpha.v = Math.max(0.12, A * Math.pow(0.5, dt / 0.7));
		let motion = 0;
		for (const id of ids) {
			const p = pos.get(id);
			const a = acc.get(id);
			if (!p || !a) continue;
			if (pin?.id === id) {
				const t = target.get(id);
				if (t) {
					p.x = t.x;
					p.y = t.y;
				}
				p.vx = 0;
				p.vy = 0;
				continue;
			}
			const mass = MASS[meta(id)?.kind ?? 'agent'] ?? 1;
			const ax = (a[0] * A) / mass;
			const ay = (a[1] * A) / mass;
			const am = Math.hypot(ax, ay);
			p.vx = (p.vx + ax * dt) * damp;
			p.vy = (p.vy + ay * dt) * damp;
			const sp = Math.hypot(p.vx, p.vy);
			if (sp < 5 && am < 30) {
				p.vx = 0;
				p.vy = 0;
				continue;
			}
			if (sp > 900) {
				p.vx *= 900 / sp;
				p.vy *= 900 / sp;
			}
			p.x += p.vx * dt;
			p.y += p.vy * dt;
			motion += sp;
		}

		// A node dropped after a drag stays put until the layout has settled
		// around it, then rejoins the springs.
		if (
			pin &&
			!pin.dragging &&
			pin.released &&
			now - pin.released > 900 &&
			now - pin.since > 200 &&
			(alpha.v < 0.24 || motion / Math.max(1, ids.length) < 9)
		) {
			pin = null;
		}
	}

	// ── containers ───────────────────────────────────────────────────────
	/**
	 * The dashed box around each ownership cluster, refreshed every frame.
	 *
	 * Membership is `graph.rootOf`, which the physics already uses to keep a
	 * user's agents near one another — so the box encloses a grouping the layout
	 * was producing anyway rather than imposing a new one. A user-level service
	 * is in there too: it is reachable only by its owner's fleet. Org-level
	 * instances are absent from `rootOf` on purpose — one of those is called
	 * from several clusters, so it belongs inside none of them.
	 */
	function computeBoxes(now: number, live: Set<string>) {
		if (!graph) return;
		const members = new Map<string, string[]>();
		for (const n of graph.structural) {
			const root = graph.rootOf.get(n.id);
			if (!root || root === n.id) continue;
			const list = members.get(root);
			if (list) list.push(n.id);
			else members.set(root, [n.id]);
		}

		const stale = new Set(boxes.keys());
		for (const [root, ids] of members) {
			stale.delete(root);
			const rp = pos.get(root);
			if (!rp) {
				boxes.delete(root);
				continue;
			}
			const all = [root, ...ids];

			if (boxClosed[root]) {
				// `+N` has to count what the chip actually hides, which includes
				// anything already folded into a member by the per-node collapse.
				let count = ids.length;
				let running = 0;
				for (const id of ids) {
					count += graph.hidden.get(id) ?? 0;
					if ((lastActive.get(id) ?? 0) > now - IDLE_GRACE_MS) running++;
				}
				let held = 0;
				for (const id of waiting) if (graph.rootOf.get(resolve(id)) === root) held++;
				const anchor = lastChipAnchor.get(root);
				boxes.set(root, {
					x0: 0,
					y0: 0,
					x1: 0,
					y1: 0,
					lx: anchor?.x ?? rp.x,
					ly: anchor?.y ?? rp.y,
					ids: all,
					collapsed: true,
					centered: !anchor,
					count,
					running,
					waiting: held
				});
				continue;
			}

			// Open: hug what is actually on screen. A cluster whose agents are
			// all hidden as idle shrinks back to its user ball rather than
			// keeping a box around empty space.
			let x0 = Infinity;
			let y0 = Infinity;
			let x1 = -Infinity;
			let y1 = -Infinity;
			for (const id of all) {
				if (id !== root && !live.has(id) && !leaving.has(id)) continue;
				const p = pos.get(id);
				if (!p) continue;
				// The whole node, caption included — a box that hugs the balls
				// leaves every label hanging over its edge. `radiusOf` is the
				// fallback for a node the DOM has not laid out yet.
				const e = nodeExtent.get(id);
				const r = radiusOf(id);
				x0 = Math.min(x0, p.x + (e ? e.dx0 : -r));
				x1 = Math.max(x1, p.x + (e ? e.dx1 : r));
				y0 = Math.min(y0, p.y + (e ? e.dy0 : -r));
				y1 = Math.max(y1, p.y + (e ? e.dy1 : r));
			}
			if (!Number.isFinite(x0)) {
				boxes.delete(root);
				continue;
			}
			x0 -= BOX_PAD_X;
			x1 += BOX_PAD_X;
			// A box has to be able to hold its own name. The chip counter-scales
			// by `1/k` so its text stays readable, which means it *grows* in world
			// units as the map zooms out, while the cluster it names does not — so
			// a user with one ball under them ends up with a label wider than the
			// container it belongs to, reading as though it had come loose. The
			// padding constants are the k=1 case of this; below that the chip
			// decides. Measured, not estimated: the label is an email whose length
			// nothing here controls.
			const chip = chipPx.get(root);
			if (chip) {
				x1 = Math.max(x1, x0 + CHIP_INSET + chip.w / view.k + BOX_PAD_X);
				y0 -= Math.max(BOX_PAD_TOP, chip.h / view.k + CHIP_CLEARANCE);
			} else {
				y0 -= BOX_PAD_TOP;
			}
			y1 += BOX_PAD_BOTTOM;
			// Remembered so folding leaves the chip on the corner it was already
			// sitting on, instead of jumping to the middle of the cluster.
			lastChipAnchor.set(root, { x: x0 + CHIP_INSET, y: y0 });
			boxes.set(root, {
				x0,
				y0,
				x1,
				y1,
				lx: x0 + CHIP_INSET,
				ly: y0,
				ids: all,
				collapsed: false,
				centered: false,
				count: 0,
				running: 0,
				waiting: 0
			});
		}
		for (const root of stale) boxes.delete(root);
	}

	// ── separation ───────────────────────────────────────────────────────
	/**
	 * Everything the pointer is holding.
	 *
	 * A cluster or a ball under the pointer is never the one that moves: the
	 * human is the one placing it, and shoving it out from under them is the map
	 * arguing back.
	 */
	function heldIds(): Set<string> {
		const h = new Set<string>();
		if (pin) h.add(pin.id);
		if (groupDrag) for (const id of groupDrag.ids) h.add(id);
		return h;
	}

	/** A node's rendered extent as offsets from its anchor: the ball *and* the
	 *  caption under it, which is the wider of the two. `radiusOf` is the
	 *  fallback for a node the DOM has not laid out yet. */
	function extentOf(id: string) {
		const e = nodeExtent.get(id);
		if (e) return e;
		const r = radiusOf(id);
		return { dx0: -r, dx1: r, dy0: -r, dy1: r };
	}

	/** A node's rectangle, the same construction `computeBoxes` measures a
	 *  container with — so a ball is the same size to both. */
	function nodeRect(id: string): Rect | null {
		const p = pos.get(id);
		if (!p) return null;
		const e = extentOf(id);
		return { x0: p.x + e.dx0, x1: p.x + e.dx1, y0: p.y + e.dy0, y1: p.y + e.dy1 };
	}

	/**
	 * What a fixed-distance spring should actually hold its pair at.
	 *
	 * `base` is the layout's number, and the floor. Above it the *targets* have
	 * the say, because `separateNodes` moves a corrected node's target with it:
	 * a spring that goes on asking for the layout's number pulls the node
	 * straight back into what it was just moved off, and the two take turns
	 * forever — which on a spoke that is packed tighter than its captions fit is
	 * the only outcome, since neither the ring radii nor `ownedServiceGap` were
	 * reckoned from text nothing here controls. Reading the rest length off the
	 * targets is how the correction stops being argued with; `setGraph` re-seeds
	 * them, so a new fleet starts from the layout's numbers again.
	 */
	function restLength(anchor: string, id: string, base: number): number {
		const ta = target.get(anchor);
		const tb = target.get(id);
		if (!ta || !tb) return base;
		return Math.max(base, Math.hypot(tb.x - ta.x, tb.y - ta.y));
	}

	/**
	 * The shortest distance along `ux,uy` at which two nodes clear each other by
	 * `NODE_GAP` — the floor under the rest length of any spring holding a pair
	 * at a set distance.
	 *
	 * A spring that asks for a distance at which the two overlap is one
	 * `separateNodes` spends every frame arguing with, and neither wins: the
	 * pass moves them apart by what is drawn, the spring pulls them back to what
	 * it was told, and a settled map twitches forever. The same reasoning as the
	 * container that has to be big enough for its own name — a ring has to be
	 * wide enough for the names on it, and the names are captions whose length
	 * nothing here controls.
	 *
	 * Clearing on *either* axis is enough, so the smaller of the two demands
	 * wins: two balls side by side need the width of both captions between them,
	 * but one above the other needs only their heights.
	 */
	function clearance(a: string, b: string, ux: number, uy: number): number {
		const ea = extentOf(a);
		const eb = extentOf(b);
		// `b` sits at `a + s·(ux,uy)`. Which of its edges has to clear which of
		// `a`'s depends on the side it is approaching from.
		const sx =
			ux > 0
				? (ea.dx1 - eb.dx0 + NODE_GAP) / ux
				: ux < 0
					? (ea.dx0 - eb.dx1 - NODE_GAP) / ux
					: Infinity;
		const sy =
			uy > 0
				? (ea.dy1 - eb.dy0 + NODE_GAP) / uy
				: uy < 0
					? (ea.dy0 - eb.dy1 - NODE_GAP) / uy
					: Infinity;
		const need = Math.min(sx, sy);
		// Neither axis asked for anything, which means there was no direction to
		// reckon along: the two are exactly on top of each other. Demand nothing
		// rather than infinity — a rest length of `Infinity` is a force of
		// `-Infinity`, and one NaN position takes the whole map with it. The
		// repulsion nudges a coincident pair apart on its own, and the frame
		// after that there is a direction again.
		return Number.isFinite(need) ? need : 0;
	}

	/**
	 * Move overlapping nodes apart, by moving them rather than by asking.
	 *
	 * The repulsion in `simulate` is a force, and a force settles wherever it
	 * balances whatever pulls the other way — the same draw the containers used
	 * to settle for. It also reasons in `radiusOf`, a circle around the ball,
	 * while what a reader sees is the ball *and* its caption, and the caption is
	 * the wider of the two. Two balls the springs consider comfortably apart can
	 * have their labels lying across each other, and siblings on one ring, whose
	 * minimum is only `pad + 18`, routinely do.
	 *
	 * So this measures what is drawn and has the last word on it. It runs before
	 * `computeBoxes` deliberately: these are individual balls moving, and a
	 * container is built to hug its members, so a correction made after the
	 * rectangle was measured would leave `draw` stroking an outline a frame
	 * behind the cluster inside it. A crowded ring pushes itself apart and its
	 * box grows to hold it — the map spreads rather than lie about what is on
	 * top of what.
	 */
	function separateNodes(live: Set<string>) {
		const ids: string[] = [];
		const rects: Rect[] = [];
		for (const id of live) {
			// A leaving node is mid-transition, and `measureNodes` declines to
			// measure one for the same reason: its extent describes where it is
			// going, not how big it is.
			if (leaving.has(id)) continue;
			const r = nodeRect(id);
			if (!r) continue;
			ids.push(id);
			rects.push(r);
		}
		if (ids.length < 2) return;
		const held = heldIds();

		// A few passes: separating one pair can push a ball into a third.
		for (let pass = 0; pass < SEPARATION_PASSES; pass++) {
			let moved = false;
			for (let i = 0; i < ids.length; i++) {
				const heldA = held.has(ids[i]);
				for (let j = i + 1; j < ids.length; j++) {
					const heldB = held.has(ids[j]);
					if (heldA && heldB) continue;
					const c = contact(rects[i], rects[j], NODE_GAP);
					if (!c) continue;
					// Half each, unless one of them is not free to move.
					const shareA = heldA ? 0 : heldB ? c.mag : c.mag / 2;
					const shareB = heldB ? 0 : heldA ? c.mag : c.mag / 2;
					if (shareA) {
						translateNode(ids[i], c.ux * shareA, c.uy * shareA);
						shift(rects[i], c.ux * shareA, c.uy * shareA);
					}
					if (shareB) {
						translateNode(ids[j], -c.ux * shareB, -c.uy * shareB);
						shift(rects[j], -c.ux * shareB, -c.uy * shareB);
					}
					moved = true;
				}
			}
			if (!moved) break;
		}
	}

	/**
	 * Move overlapping containers, chips and loose nodes apart, by moving them
	 * rather than by asking.
	 *
	 * The springs in `simulate` do the smooth work, but a force can only ever
	 * reach the point where it balances whatever pulls the other way — and every
	 * cluster is held to a slot on a ring whose radius knows nothing about how
	 * big the cluster grew, while an org-level service is held to that ring
	 * harder than anything else on the map. Two service-heavy fleets on adjacent
	 * slots settle with their boxes a few units into each other; a service
	 * settles a little way off its ring and a little way inside a container.
	 * Both pushes were working. They had an opponent, and drew.
	 *
	 * So the last word is positional. Boxes have just been rebuilt from the
	 * positions this frame produced; any pair closer than its clearance —
	 * touching reads no better than overlapping — is separated by translating
	 * whole clusters, and `draw` strokes the corrected rectangles. A contact
	 * constraint cannot be out-pulled the way a force can.
	 *
	 * Three kinds of thing are separated, because all three make the same claim
	 * when they lie on top of each other: a container, the chip a folded
	 * container leaves behind, and a node that belongs to no open container —
	 * an org-level service, the aggregate, an agent whose owner is off the map.
	 * A *member* of a container is not one of them: its cluster's rectangle
	 * already encloses it, so a member intruding on another container means the
	 * two rectangles intersect, which is said here by moving both clusters whole
	 * rather than by shearing one ball out of the fleet it is drawn with.
	 *
	 * `SEPARATION_SLOP` is what stops that from becoming a per-frame shimmer:
	 * the ring spring pulls back a fraction of a unit each frame and would be
	 * corrected right back out again forever. Below the slop the overlap is a
	 * sliver no zoom level can show, and it is left alone.
	 */
	function separateShapes(live: Set<string>) {
		const held = heldIds();
		const shapes: Shape[] = [];
		const boxed = new Set<string>();

		for (const [root, b] of boxes) {
			for (const id of b.ids) boxed.add(id);
			const isHeld = b.ids.some((id) => held.has(id));
			if (!b.collapsed) {
				shapes.push({
					cluster: true,
					root,
					b,
					rect: { x0: b.x0, y0: b.y0, x1: b.x1, y1: b.y1 },
					held: isHeld
				});
				continue;
			}
			// A folded cluster *is* its chip. The box behind it is meaningless
			// while collapsed, but the chip is a real thing on the map, left on
			// whatever corner the cluster was folded from — and it can be left on
			// top of a container. It counter-scales to stay readable, so its world
			// size is the measured screen size over the zoom, and it hangs down and
			// right from its anchor unless it has none yet and centres on the root.
			const c = chipPx.get(root);
			if (!c?.w) continue;
			const w = c.w / view.k;
			const h = c.h / view.k;
			const x0 = b.centered ? b.lx - w / 2 : b.lx;
			const y0 = b.centered ? b.ly - h / 2 : b.ly;
			shapes.push({
				cluster: true,
				root,
				b,
				rect: { x0, y0, x1: x0 + w, y1: y0 + h },
				held: isHeld
			});
		}

		// An open container's own chip needs no rule: `computeBoxes` reserves the
		// band it hangs in, so it is already inside the rectangle above.
		for (const id of live) {
			if (boxed.has(id) || leaving.has(id)) continue;
			const rect = nodeRect(id);
			if (!rect) continue;
			shapes.push({ cluster: false, id, rect, held: held.has(id) });
		}
		if (shapes.length < 2) return;

		// A few passes: separating one pair can push a shape into a third.
		for (let pass = 0; pass < SEPARATION_PASSES; pass++) {
			let moved = false;
			for (let i = 0; i < shapes.length; i++) {
				const A = shapes[i];
				for (let j = i + 1; j < shapes.length; j++) {
					const B = shapes[j];
					// Two loose balls are `separateNodes`' business, and it has
					// already settled them on the same rendered extents.
					if (!A.cluster && !B.cluster) continue;
					if (A.held && B.held) continue;
					// Containers insist on `BOX_GAP` from each other; a non-member
					// keeps the smaller `STRAY_GAP` from one, which is the clearance
					// the stray force asks for.
					const c = contact(A.rect, B.rect, A.cluster && B.cluster ? BOX_GAP : STRAY_GAP);
					if (!c) continue;
					// Half each between two containers. Between a node and a
					// container the node takes the bulk and the cluster takes
					// `STRAY_REACTION` back: all of it on the cluster and one loose
					// ball could walk a whole fleet across the map, and all of it on
					// the node ignores that it got there by being pushed into.
					const fracA =
						A.cluster === B.cluster ? 0.5 : A.cluster ? STRAY_REACTION : 1 - STRAY_REACTION;
					const shareA = A.held ? 0 : B.held ? c.mag : c.mag * fracA;
					const shareB = B.held ? 0 : A.held ? c.mag : c.mag * (1 - fracA);
					if (shareA) moveShape(A, c.ux * shareA, c.uy * shareA);
					if (shareB) moveShape(B, -c.ux * shareB, -c.uy * shareB);
					moved = true;
				}
			}
			if (!moved) break;
		}
	}

	/** Move a shape, and the rectangle the pass is testing against with it. */
	function moveShape(s: Shape, dx: number, dy: number) {
		if (s.cluster) translateCluster(s.root, s.b, dx, dy);
		else translateNode(s.id, dx, dy);
		shift(s.rect, dx, dy);
	}

	/**
	 * Slide one node, position and target together.
	 *
	 * Correcting only the position leaves whatever spring holds this node
	 * pulling towards where it used to be, and it creeps back a fraction of a
	 * unit per frame until it crosses the slop and is corrected out again — a
	 * settled map that twitches once a second forever. Moving the target is what
	 * makes the correction hold, and it is what the code already does for a
	 * cluster a human drags.
	 *
	 * Not added to `manualTargets`, though: that set exists so a *gesture*
	 * outlives a fleet refetch. This is derived from the layout, so it should be
	 * re-derived from the next one — `setGraph` re-seeds, and if things still
	 * overlap the next frame corrects them again.
	 *
	 * Velocity is left alone: this is a correction, not a shove, and handing the
	 * node momentum would make it overshoot and swing back.
	 */
	function translateNode(id: string, dx: number, dy: number) {
		const p = pos.get(id);
		if (!p) return;
		p.x += dx;
		p.y += dy;
		const t = target.get(id);
		// A fresh object: `setGraph` stores the graph's own target objects by
		// reference, and mutating one would edit `graph.targets` underneath
		// everything else that reads it.
		if (t) target.set(id, { x: t.x + dx, y: t.y + dy });
	}

	/** Slide a whole cluster: its members, the rectangle drawn around them, and
	 *  the corner its name chip sits on. */
	function translateCluster(root: string, b: Box, dx: number, dy: number) {
		for (const id of b.ids) translateNode(id, dx, dy);
		b.x0 += dx;
		b.x1 += dx;
		b.y0 += dy;
		b.y1 += dy;
		b.lx += dx;
		b.ly += dy;
		const anchor = lastChipAnchor.get(root);
		if (anchor) lastChipAnchor.set(root, { x: anchor.x + dx, y: anchor.y + dy });
	}

	/** One path for every open box: they never overlap, so a single nonzero
	 *  fill is both cheaper and free of double-darkened seams. */
	function drawBoxes(ctx: CanvasRenderingContext2D) {
		let any = false;
		ctx.save();
		ctx.beginPath();
		for (const b of boxes.values()) {
			if (b.collapsed) continue;
			any = true;
			const w = b.x1 - b.x0;
			const h = b.y1 - b.y0;
			if (typeof ctx.roundRect === 'function') ctx.roundRect(b.x0, b.y0, w, h, BOX_RADIUS);
			else ctx.rect(b.x0, b.y0, w, h);
		}
		if (any) {
			ctx.globalAlpha = 0.04;
			ctx.fillStyle = colors.tree;
			ctx.fill();
			ctx.globalAlpha = 0.28;
			ctx.lineWidth = 1;
			ctx.setLineDash([4, 5]);
			ctx.strokeStyle = colors.tree;
			ctx.stroke();
		}
		ctx.restore();
	}

	/**
	 * Read back what the browser actually laid out for each node.
	 *
	 * The alternative is arithmetic over the stylesheet — ball diameter, caption
	 * `max-width`, the caption's own `scale()` — which is a copy of the CSS that
	 * goes stale the first time someone changes it. Reading the rendered box is
	 * self-maintaining, and it is the only way to know how wide a caption ended
	 * up when it may have been ellipsised.
	 *
	 * The caption's `scale()` applies after layout, so it can spill past its
	 * parent's border box: union the two rather than trusting the parent.
	 */
	function measureNodes() {
		if (!nodeEls.size) return;
		const stageRect = stage.getBoundingClientRect();
		const k = view.k;
		for (const [id, el] of nodeEls) {
			const p = pos.get(id);
			// A leaving node is mid-transition and translating; its rect right now
			// describes where it is going, not how big it is.
			if (!p || el.classList.contains('is-leaving')) continue;
			const inner = el.querySelector('.lm-node-in');
			if (!inner) continue;
			const r = inner.getBoundingClientRect();
			if (!r.width) continue;
			const cap = inner.querySelector('.lm-cap');
			const c = cap?.getBoundingClientRect();
			const ax = stageRect.left + view.tx + p.x * k;
			const ay = stageRect.top + view.ty + p.y * k;
			nodeExtent.set(id, {
				dx0: ((c ? Math.min(r.left, c.left) : r.left) - ax) / k,
				dx1: ((c ? Math.max(r.right, c.right) : r.right) - ax) / k,
				dy0: ((c ? Math.min(r.top, c.top) : r.top) - ay) / k,
				dy1: ((c ? Math.max(r.bottom, c.bottom) : r.bottom) - ay) / k
			});
		}
	}

	/** Chip classes and text. Cheap enough at the UI cadence; the transform is
	 *  separate, because that has to track the view every frame. */
	function syncChips() {
		const h = hits;
		for (const [root, el] of chipEls) {
			// Before the `b` check: a chip with no box yet still has to be measured,
			// or the box that is about to want its width never gets one.
			chipPx.set(root, { w: el.offsetWidth, h: el.offsetHeight });
			const b = boxes.get(root);
			if (!b) {
				el.classList.remove('is-live');
				continue;
			}
			el.classList.add('is-live');
			el.classList.toggle('is-closed', b.collapsed);
			el.classList.toggle('is-active', b.collapsed && b.running > 0);
			el.classList.toggle('is-waiting', b.collapsed && b.waiting > 0);
			// A search that matches nothing in this cluster dims its chip the way
			// it dims the balls — otherwise a folded cluster looks like a hit.
			el.classList.toggle('is-dim', h ? !b.ids.some((id) => h.has(id)) : false);
			const count = el.querySelector('.lm-chip-count');
			if (count) count.textContent = b.collapsed ? `+${b.count}` : '';
			const act = el.querySelector('.lm-chip-act');
			if (!act) continue;
			// Waiting outranks running, same as the node states: a fold that hides
			// a gated call must not report itself as merely busy.
			if (!b.collapsed) act.textContent = '';
			else if (b.waiting > 0) act.textContent = `${b.waiting} waiting`;
			else if (b.running > 0) act.textContent = `${b.running} active`;
			else act.textContent = '';
		}
	}

	// ── canvas ───────────────────────────────────────────────────────────
	function draw(
		now: number,
		edges: { id: string; from: string; to: string; tree: boolean }[],
		edgeBusy: Set<string>,
		fadeOf: (id: string) => number,
		live: Set<string>
	) {
		const W = stage.clientWidth;
		const H = stage.clientHeight;
		const dpr = Math.min(2, window.devicePixelRatio || 1);
		if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) {
			canvas.width = Math.round(W * dpr);
			canvas.height = Math.round(H * dpr);
		}
		const ctx = canvas.getContext('2d');
		if (!ctx) return;
		const { k, tx, ty } = view;
		ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
		ctx.clearRect(0, 0, W, H);
		ctx.setTransform(dpr * k, 0, 0, dpr * k, dpr * tx, dpr * ty);
		ctx.lineCap = 'round';

		/** Edge endpoints, trimmed back to the rim of each ball. */
		const seg = (from: string, to: string): [number, number, number, number] | null => {
			const a = pos.get(from);
			const b = pos.get(to);
			if (!a || !b) return null;
			let dx = b.x - a.x;
			let dy = b.y - a.y;
			const d = Math.hypot(dx, dy) || 1;
			dx /= d;
			dy /= d;
			const ra = radiusOf(from) + 3;
			const rb = radiusOf(to) + 3;
			return [a.x + dx * ra, a.y + dy * ra, b.x - dx * rb, b.y - dy * rb];
		};

		const visible = (id: string) => live.has(id) || leaving.has(id);

		// Under the edges: a container is ground, not content.
		drawBoxes(ctx);

		for (const e of edges) {
			if (!visible(e.from) || !visible(e.to)) continue;
			const s = seg(e.from, e.to);
			if (!s) continue;
			const fade = Math.min(fadeOf(e.from), fadeOf(e.to));
			if (fade <= 0) continue;
			const dim = hits && !(hits.has(e.from) || hits.has(e.to));
			const busy = edgeBusy.has(e.id);
			// An org-level instance collects an edge from every cluster that ever
			// called it, and at rest that thicket reads as structure it is not.
			// Owned traffic keeps its weight, and so does an unlisted node's: we
			// do not know it is shared, only that we could not list it.
			const toMeta = meta(e.to);
			const shared =
				!e.tree && toMeta?.kind === 'service' && !toMeta.owner && !toMeta.unlisted;
			ctx.beginPath();
			ctx.moveTo(s[0], s[1]);
			ctx.lineTo(s[2], s[3]);
			ctx.lineWidth = e.tree ? 1.5 : busy ? 1.2 : 1;
			ctx.globalAlpha =
				(dim ? 0.05 : busy ? (shared ? 0.31 : 0.5) : e.tree ? 0.62 : shared ? 0.13 : 0.3) * fade;
			ctx.strokeStyle = busy ? colors.primary : e.tree ? colors.tree : colors.edge;
			ctx.stroke();
		}

		ctx.globalAlpha = 1;
		for (const c of packets) {
			if (!c.edge) continue;
			const [f, t2] = c.edge.split('>');
			if (!visible(f) || !visible(t2)) continue;
			if (hits && !(hits.has(f) || hits.has(t2))) continue;
			const s = seg(f, t2);
			if (!s) continue;
			const fade = Math.min(fadeOf(f), fadeOf(t2));
			if (fade <= 0) continue;
			const x = s[0] + (s[2] - s[0]) * c.t;
			const y = s[1] + (s[3] - s[1]) * c.t;
			let col = colors.primary;
			let r = 3.4;
			if (c.phase === 'res') col = outcomeColor(c.outcome);
			if (c.phase === 'hold') {
				// Parked at the far end while the upstream works. Breathing, so
				// a slow call reads as slow rather than as a stalled render.
				r = 4 + Math.sin(now / 260) * 1.4;
			}
			ctx.globalAlpha = fade;
			ctx.shadowColor = col;
			ctx.shadowBlur = c.phase === 'hold' ? 14 : 9;
			ctx.fillStyle = col;
			ctx.beginPath();
			ctx.arc(x, y, r, 0, Math.PI * 2);
			ctx.fill();
			ctx.shadowBlur = 0;
			ctx.globalAlpha = 1;
		}

		layer.style.transform = `translate(${tx}px,${ty}px) scale(${k})`;
		chipLayer.style.transform = `translate(${tx}px,${ty}px) scale(${k})`;
		for (const [id, el] of nodeEls) {
			const p = pos.get(id);
			if (p) el.style.transform = `translate(${p.x}px,${p.y}px)`;
		}
		// Chips ride the map but not its zoom: the counter-scale keeps their text
		// at a constant size, so a name is still readable at 30%.
		for (const [root, el] of chipEls) {
			const b = boxes.get(root);
			if (!b) continue;
			el.style.transform =
				`translate(${b.lx}px,${b.ly}px) scale(${1 / k})` +
				(b.centered ? ' translate(-50%,-50%)' : '');
		}
	}

	function outcomeColor(o?: CallOutcome): string {
		if (o === 'denied' || o === 'rejected') return colors.danger;
		if (o === 'failed' || o === 'upstream_error') return colors.warning;
		return colors.success;
	}

	/** Calls currently touching a node, for its tooltip. */
	function callsFor(nodeId: string): TooltipCall[] {
		return packets
			.filter((c) => resolve(c.from) === nodeId || resolve(c.to) === nodeId)
			.map((c) => ({ label: meta(c.to)?.label ?? c.to, waiting: c.phase === 'hold' }));
	}

	function destroy() {
		cancelAnimationFrame(raf);
		themeObserver.disconnect();
		stage.removeEventListener('wheel', onWheel);
	}

	raf = requestAnimationFrame(frame);

	return {
		setGraph,
		setHits,
		setHideIdle,
		setBoxClosed,
		registerNode,
		registerChip,
		startCall,
		finishCall,
		setWaiting,
		clearTraffic,
		callsFor,
		zoomBy,
		recenter,
		setHover,
		onStagePointerDown,
		onNodePointerDown,
		onChipPointerDown,
		consumeGroupDrag,
		onPointerMove,
		onPointerUp,
		destroy
	};
}

export type Sim = ReturnType<typeof createSim>;
