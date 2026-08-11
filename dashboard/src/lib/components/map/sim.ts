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
import type { Graph, NodeKind } from './graph';

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
}

export function createSim(mounts: SimMounts, cb: SimCallbacks) {
	const { stage, canvas, layer } = mounts;

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
			// from the layout would yank it back mid-gesture.
			if (pin?.id === id) continue;
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

	function registerNode(id: string, el: HTMLElement | null) {
		if (el) nodeEls.set(id, el);
		else nodeEls.delete(id);
	}

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
		if (graph) for (const [id, t] of graph.targets) target.set(id, t);
		fitView();
		alpha.v = 1;
	}

	// ── pointer ──────────────────────────────────────────────────────────
	const isOverlay = (e: Event) =>
		e.target instanceof Element &&
		!!(e.target.closest('.lm-node-in') || e.target.closest('.lm-panel'));

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

	function onPointerMove(e: PointerEvent) {
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
			const l = leaving.get(id);
			if (l != null) return Math.max(0, 1 - (now - l) / 360);
			const t0 = seenAt.get(id);
			return t0 == null ? 0 : Math.min(1, (now - t0) / 110);
		};

		simulate(dt, now, edges);
		draw(now, edges, edgeBusy, fadeOf, live);

		uiAcc += dt;
		if (uiAcc > 0.22) {
			uiAcc = 0;
			for (const [id, el] of nodeEls) {
				el.classList.toggle('is-running', nodeState.get(id) === 'running');
				el.classList.toggle('is-waiting', nodeState.get(id) === 'waiting');
			}
			for (const [id, t] of leaving) if (now - t > 400) leaving.delete(id);
			cb.onShownChange([...live, ...[...leaving.keys()].filter((i) => !live.has(i))]);
			cb.onZoomChange(Math.round(view.k * 100));
		}

		raf = requestAnimationFrame(frame);
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
			// Services and users hold their ring; agents are free to swing.
			if (m.kind === 'service') {
				a[0] += (t.x - p.x) * 3 * mass;
				a[1] += (t.y - p.y) * 3 * mass;
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

		for (const e of edges) {
			if (!visible(e.from) || !visible(e.to)) continue;
			const s = seg(e.from, e.to);
			if (!s) continue;
			const fade = Math.min(fadeOf(e.from), fadeOf(e.to));
			if (fade <= 0) continue;
			const dim = hits && !(hits.has(e.from) || hits.has(e.to));
			const busy = edgeBusy.has(e.id);
			ctx.beginPath();
			ctx.moveTo(s[0], s[1]);
			ctx.lineTo(s[2], s[3]);
			ctx.lineWidth = e.tree ? 1.5 : busy ? 1.2 : 1;
			ctx.globalAlpha = (dim ? 0.05 : busy ? 0.5 : e.tree ? 0.62 : 0.3) * fade;
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
		for (const [id, el] of nodeEls) {
			const p = pos.get(id);
			if (p) el.style.transform = `translate(${p.x}px,${p.y}px)`;
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
		registerNode,
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
		onPointerMove,
		onPointerUp,
		destroy
	};
}

export type Sim = ReturnType<typeof createSim>;
