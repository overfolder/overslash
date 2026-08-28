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
/** Penetration below this is not worth keeping the whole layout awake for. */
const SEPARATION_EPSILON = 4;
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
	/** The root and its members, cached for the box-vs-box separation pass. */
	ids: string[];
	collapsed: boolean;
	/** No remembered anchor yet — the chip centres on the root instead. */
	centered: boolean;
	count: number;
	running: number;
	waiting: number;
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

		// `simulate` reads the previous frame's boxes for the box-vs-box push;
		// `computeBoxes` then refreshes them from the positions it just moved,
		// so the outline `draw` strokes is never a frame behind its balls.
		simulate(dt, now, edges);
		computeBoxes(now, live);
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
	function simulate(dt: number, now: number, edges: { from: string; to: string; tree: boolean }[]) {
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
			const L = graph.ownedServiceGap;
			let dx = b.x - a.x;
			let dy = b.y - a.y;
			const d = Math.hypot(dx, dy) || 1;
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
			const L = e.tree
				? src.kind === 'user' || src.kind === 'org'
					? SHELL_R
					: SHELL_R * 0.66
				: 340;
			const k = e.tree ? SPRING_K : SPRING_K * 0.024;
			let dx = b.x - a.x;
			let dy = b.y - a.y;
			const d = Math.hypot(dx, dy) || 1;
			const f = (d - L) * k;
			dx /= d;
			dy /= d;
			fa[0] += dx * f;
			fa[1] += dy * f;
			fb[0] -= dx * f;
			fb[1] -= dy * f;
		}

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
				const min = bothUsers
					? USER_GAP
					: sameTree
						? Math.max(56, pad + 18)
						: Math.max(112, pad + 60);
				let dx = b.x - a.x;
				let dy = b.y - a.y;
				let d2 = dx * dx + dy * dy;
				if (d2 > min * min) continue;
				if (d2 === 0) {
					// Exactly coincident: no separating direction exists.
					// Nudge deterministically rather than dividing by zero.
					dx = i % 2 === 0 ? 0.5 : -0.5;
					dy = 0.5;
					d2 = 0.5;
				}
				const d = Math.sqrt(d2);
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
		for (const b of openBoxes) {
			const members = new Set(b.ids);
			for (const id of ids) {
				if (members.has(id) || pin?.id === id) continue;
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
				// The *penetration*, not the exit distance: `m` is measured from a
				// rect already inflated by `STRAY_GAP`, so a stray resting exactly
				// at its clearance still reports `m === STRAY_GAP` and would hold
				// the whole layout above the cooling floor forever. Same
				// convention as the box pair above, which reports `mag - BOX_GAP`.
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
