<script lang="ts">
	import { onMount } from 'svelte';
	import { onEvent, eventStream, type StreamEvent } from '$lib/stores/events.svelte';
	import type { Identity, ServiceInstanceSummary } from '$lib/types';
	import { buildGraph, serviceNodeId, type CollapseState, type MapNode } from './graph';
	import { createSim, SIZES, type CallOutcome, type Sim, type TooltipCall } from './sim';

	let {
		identities = [],
		services = [],
		onUnknownActor = () => {}
	}: {
		identities?: Identity[];
		services?: ServiceInstanceSummary[];
		/** An event named an identity we have never heard of — the fleet
		 *  snapshot is stale. The page decides whether to refetch. */
		onUnknownActor?: () => void;
	} = $props();

	interface ActionEventData {
		call_id?: string;
		actor_identity_id?: string;
		service?: string | null;
		action?: string | null;
		outcome?: string;
	}
	interface ApprovalEventData {
		approval_id?: string;
		identity_id?: string;
	}

	let collapse = $state<CollapseState>({ users: false, agents: false, subagents: true });
	/** Per-node open/closed, overriding the global chips. */
	let overrides = $state<Record<string, boolean>>({});
	/** Cluster root → folded into its container chip. A plain record rather than
	 *  a Set: `$state` deep-proxies objects and arrays, not Sets. */
	let boxClosed = $state<Record<string, boolean>>({});
	let hideIdle = $state(true);
	let query = $state('');
	let shown = $state<string[]>([]);
	/** Service node ids seen on the stream but missing from `services` — a
	 *  user-level instance an admin can watch but not list, or raw HTTP. */
	let extraServices = $state<string[]>([]);
	let zoom = $state(75);
	let tip = $state<{
		node: MapNode;
		x: number;
		y: number;
		rows: TooltipCall[];
		more: number;
	} | null>(null);

	// Avatar URLs the browser could not load — a provider rotates them when the
	// user changes their photo, and the one we snapshotted keeps 404ing until
	// they next sign in. Remembered per URL so the node falls back to its
	// monogram once and does not retry on every re-render.
	let brokenPictures = $state<string[]>([]);

	let stage: HTMLElement;
	let canvas: HTMLCanvasElement;
	let layer: HTMLElement;
	let chipLayer: HTMLElement;
	let sim: Sim | null = null;
	/** The simulation exists. Node elements arrive through `shown`, which is
	 *  empty until it does — but the container chips would otherwise render on
	 *  the very first pass and register against a `sim` that is still null. */
	let ready = $state(false);

	const graph = $derived(buildGraph(identities, services, extraServices, collapse, overrides));

	const counts = $derived.by(() => {
		let users = 0;
		let agents = 0;
		let subagents = 0;
		for (const n of graph.byId.values()) {
			if (n.kind === 'user') users++;
			else if (n.kind === 'agent') agents++;
			else if (n.kind === 'subagent') subagents++;
		}
		return { users, agents, subagents };
	});

	const lanes = $derived([
		{ id: 'users' as const, label: 'Users', count: counts.users },
		{ id: 'agents' as const, label: 'Agents', count: counts.agents },
		{ id: 'subagents' as const, label: 'Subagents', count: counts.subagents }
	]);

	/** Search matches, mapped onto whichever node currently stands for them. */
	const hits = $derived.by(() => {
		const q = query.trim().toLowerCase();
		if (!q) return null;
		const s = new Set<string>();
		for (const n of graph.byId.values()) {
			if (n.label.toLowerCase().includes(q)) s.add(graph.resolve(n.id));
		}
		return s;
	});

	/**
	 * Cluster roots worth drawing a container around: a user (or the org
	 * aggregate) with at least one agent or subagent standing under it.
	 *
	 * Folding the Agents lane leaves every root memberless, so the boxes go with
	 * it — which is right, since there is nothing left to enclose.
	 */
	const boxRoots = $derived.by(() => {
		const roots: string[] = [];
		const seen = new Set<string>();
		for (const n of graph.structural) {
			const root = graph.rootOf.get(n.id);
			if (!root || root === n.id || seen.has(root)) continue;
			seen.add(root);
			roots.push(root);
		}
		return roots;
	});

	/** Folded away inside a collapsed container. Mirrors the simulation's own
	 *  test, so a fold takes effect on the click rather than on the next
	 *  `onShownChange` up to 220ms later. */
	function hiddenByBox(n: MapNode): boolean {
		if (n.kind === 'user' || n.kind === 'org') return !!boxClosed[n.id];
		const root = graph.rootOf.get(n.id);
		return !!root && root !== n.id && !!boxClosed[root];
	}

	const shownNodes = $derived(
		shown
			.map((id) => graph.byId.get(id))
			.filter((n): n is MapNode => !!n && !hiddenByBox(n))
	);

	// ── approval bookkeeping ─────────────────────────────────────────────
	// `approval.resolved` carries no requester, so the amber state can only be
	// cleared by remembering who each pending approval belonged to. A set per
	// identity, because one agent can be blocked on several at once and
	// clearing the first must not un-light the rest.
	const pendingByIdentity = new Map<string, Set<string>>();
	const identityByApproval = new Map<string, string>();

	function markPending(approvalId: string, identityId: string) {
		identityByApproval.set(approvalId, identityId);
		const set = pendingByIdentity.get(identityId) ?? new Set<string>();
		set.add(approvalId);
		pendingByIdentity.set(identityId, set);
		sim?.setWaiting(identityId, true);
	}

	function clearPending(approvalId: string) {
		const identityId = identityByApproval.get(approvalId);
		if (!identityId) return;
		identityByApproval.delete(approvalId);
		const set = pendingByIdentity.get(identityId);
		set?.delete(approvalId);
		if (!set || set.size === 0) {
			pendingByIdentity.delete(identityId);
			sim?.setWaiting(identityId, false);
		}
	}

	function handleAction(e: StreamEvent<ActionEventData>) {
		const { call_id: callId, actor_identity_id: actor } = e.data;
		if (!callId || !actor) return;
		const to = serviceNodeId(e.data.service);
		// Both endpoints may be new to us. A service gets a node on the spot;
		// an identity has to come from the API, so ask the page to refetch.
		if (!graph.byId.has(to) && !extraServices.includes(to)) {
			extraServices = [...extraServices, to];
		}
		if (!graph.byId.has(actor)) onUnknownActor();
		if (e.type === 'action.called') sim?.startCall(callId, actor, to);
		else sim?.finishCall(callId, actor, to, (e.data.outcome as CallOutcome) ?? 'called');
	}

	onMount(() => {
		sim = createSim(
			{ stage, canvas, layer, chipLayer },
			{
				onShownChange: (ids) => {
					// Fires four times a second whether or not anything moved.
					// Comparing first keeps the `{#each}` from re-keying a list
					// that is usually identical to the last one.
					if (ids.length === shown.length && ids.every((id, i) => shown[i] === id)) return;
					shown = ids;
				},
				onZoomChange: (pct) => {
					if (pct !== zoom) zoom = pct;
				}
			}
		);
		sim.setGraph(graph);
		ready = true;

		const offAction = onEvent<ActionEventData>(['action.called', 'action.completed'], handleAction);
		const offApproval = onEvent<ApprovalEventData>(
			['approval.pending', 'approval.resolved'],
			(e) => {
				if (e.type === 'approval.pending') {
					if (e.data.approval_id && e.data.identity_id)
						markPending(e.data.approval_id, e.data.identity_id);
				} else if (e.data.approval_id) {
					clearPending(e.data.approval_id);
				}
			}
		);
		// The stream died and came back: anything in flight may have finished
		// unseen, and any approval may have been resolved. Start clean rather
		// than leave a permanently amber node behind.
		const offResync = onEvent(['stream.resync'], () => {
			pendingByIdentity.clear();
			identityByApproval.clear();
			sim?.clearTraffic();
		});

		return () => {
			ready = false;
			offAction();
			offApproval();
			offResync();
			sim?.destroy();
			sim = null;
		};
	});

	$effect(() => {
		sim?.setGraph(graph);
	});
	$effect(() => {
		sim?.setHits(hits);
	});
	$effect(() => {
		sim?.setHideIdle(hideIdle);
	});
	$effect(() => {
		// Spread rather than hand over the `$state` proxy: the simulation reads
		// this on every frame, and it is deliberately outside Svelte.
		sim?.setBoxClosed({ ...boxClosed });
	});

	/** Registers the element with the simulation, which moves it every frame. */
	function tracked(node: HTMLElement, id: string) {
		sim?.registerNode(id, node);
		return {
			destroy() {
				sim?.registerNode(id, null);
			}
		};
	}

	/** The same, for a container's name chip. */
	function trackedChip(node: HTMLElement, root: string) {
		sim?.registerChip(root, node);
		return {
			destroy() {
				sim?.registerChip(root, null);
			}
		};
	}

	function toggleBox(root: string) {
		boxClosed = { ...boxClosed, [root]: !boxClosed[root] };
	}

	function hasChildren(n: MapNode): boolean {
		if (n.kind === 'org' || n.kind === 'user') return true;
		return (n.sub ?? 0) > 0;
	}

	function toggleNode(n: MapNode) {
		if (n.kind === 'service') return;
		if (!hasChildren(n)) return;
		const now = graph.closedFor(n.id, n.kind);
		overrides = { ...overrides, [n.id]: !now };
	}

	function toggleLane(lane: keyof CollapseState) {
		collapse = { ...collapse, [lane]: !collapse[lane] };
		// Per-node overrides were answers to the previous global state; keeping
		// them would make the chip look inert on whichever nodes had one.
		overrides = {};
	}

	function showTip(e: MouseEvent, n: MapNode) {
		const r = stage.getBoundingClientRect();
		const rows = sim?.callsFor(n.id) ?? [];
		tip = {
			node: n,
			x: e.clientX - r.left + 16,
			y: e.clientY - r.top + 14,
			rows: rows.slice(0, 4),
			more: Math.max(0, rows.length - 4)
		};
	}

	function tipSubtitle(n: MapNode): string {
		if (n.kind === 'service') return n.status ?? 'Service';
		if (n.kind === 'org') return 'All users';
		if (n.kind === 'user') return `Owner · ${n.sub ?? 0} agents`;
		const kind = n.kind === 'agent' ? 'Agent' : 'Subagent';
		return `${kind} · ${n.sub ?? 0} subagents`;
	}
</script>

<div
	class="lm-root"
	style:--lm-user="{SIZES.user}px"
	style:--lm-agent="{SIZES.agent}px"
	style:--lm-svc="{SIZES.service}px"
>
	<!-- Pointer handling lives in the simulation: pan, zoom and node drag all
	     mutate the same view/position state it renders from. -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="lm-stage"
		bind:this={stage}
		onpointerdown={(e) => sim?.onStagePointerDown(e)}
		onpointermove={(e) => sim?.onPointerMove(e)}
		onpointerup={() => sim?.onPointerUp()}
		onpointercancel={() => sim?.onPointerUp()}
	>
		<canvas bind:this={canvas}></canvas>

		<div class="lm-layer" bind:this={layer}>
			{#each shownNodes as n (n.id)}
				{@const badge = graph.hidden.get(n.id) ?? 0}
				<div
					class="lm-node k-{n.kind}"
					class:is-dim={hits && !hits.has(n.id)}
					class:is-hit={hits?.has(n.id)}
					use:tracked={n.id}
				>
					<!-- svelte-ignore a11y_no_static_element_interactions -->
					<div
						class="lm-node-in"
						onpointerdown={(e) => sim?.onNodePointerDown(e, n.id)}
						ondblclick={(e) => {
							e.stopPropagation();
							toggleNode(n);
						}}
						onmouseenter={(e) => {
							sim?.setHover(n.id);
							showTip(e, n);
						}}
						onmousemove={(e) => showTip(e, n)}
						onmouseleave={() => {
							sim?.setHover(null);
							tip = null;
						}}
					>
						<div class="lm-ball">
							<!-- Monogram and avatar share one grid cell rather than
							     branching: a third-party avatar host that hangs
							     fires neither `load` nor `error`, and an `{:else}`
							     would leave the ball empty until it does. -->
							<span class="lm-ball-mono">{n.mono}</span>
							{#if n.picture && !brokenPictures.includes(n.picture)}
								<img
									class="lm-ball-img"
									src={n.picture}
									alt=""
									referrerpolicy="no-referrer"
									draggable="false"
									onerror={() => n.picture && brokenPictures.push(n.picture)}
								/>
							{:else if n.icon && !brokenPictures.includes(n.icon)}
								<!-- A brand mark: a service's catalog icon, or an agent's
								     MCP client. Same grid cell and the same broken-src list
								     as an avatar, but contained rather than cropped and on
								     its own light ground — see .lm-ball-icon. -->
								<img
									class="lm-ball-icon"
									src={n.icon}
									alt=""
									referrerpolicy="no-referrer"
									draggable="false"
									onerror={() => n.icon && brokenPictures.push(n.icon)}
								/>
							{/if}
							{#if badge}
								<button
									class="lm-badge"
									title="Expand {badge} hidden"
									onpointerdown={(e) => e.stopPropagation()}
									onclick={(e) => {
										e.stopPropagation();
										toggleNode(n);
									}}>+{badge}</button
								>
							{:else if n.kind !== 'service' && hasChildren(n)}
								<button
									class="lm-caret-btn"
									title="Collapse"
									onpointerdown={(e) => e.stopPropagation()}
									onclick={(e) => {
										e.stopPropagation();
										toggleNode(n);
									}}>▼</button
								>
							{/if}
						</div>
						{#if n.stripe}
							<div class="lm-stripe" aria-hidden="true">
								{#each n.stripe as colour, i (i)}
									<span style:background={colour}></span>
								{/each}
							</div>
						{/if}
						<div class="lm-cap">{n.label}</div>
					</div>
				</div>
			{/each}
		</div>

		<!-- Container name chips. Outside `.lm-layer` because they must not take
		     its zoom: the simulation counter-scales each one so its text stays
		     the same size however far out the map is. -->
		<div class="lm-chiplayer" bind:this={chipLayer}>
			{#each ready ? boxRoots : [] as root (root)}
				{@const label = graph.byId.get(root)?.label ?? root}
				<button
					class="lm-boxchip"
					use:trackedChip={root}
					title="{boxClosed[root] ? 'Expand' : 'Collapse'} {label} · drag to move"
					onpointerdown={(e) => sim?.onChipPointerDown(e, root)}
					onclick={() => {
						// A drag ends in a click too. Swallow that one so moving a
						// cluster does not also fold it.
						if (sim?.consumeGroupDrag()) return;
						toggleBox(root);
					}}
				>
					<span class="lm-chip-caret" aria-hidden="true">▼</span>
					<span class="lm-chip-name">{label}</span>
					<span class="lm-chip-count"></span>
					<span class="lm-chip-act"></span>
				</button>
			{/each}
		</div>

		<div class="lm-panel lm-tl">
			<div class="lm-search">
				<input bind:value={query} placeholder="Search agents, services…" />
				{#if query}
					<button class="lm-search-clear" onclick={() => (query = '')} aria-label="Clear search"
						>✕</button
					>
				{/if}
			</div>
			<div class="lm-toggles">
				{#each lanes as lane (lane.id)}
					<button
						class="lm-chip"
						class:is-off={collapse[lane.id]}
						title="{collapse[lane.id] ? 'Expand' : 'Collapse'} {lane.label}"
						onclick={() => toggleLane(lane.id)}
					>
						<span class="lm-caret">{collapse[lane.id] ? '▶' : '▼'}</span>{lane.label}
						<em>{lane.count}</em>
					</button>
				{/each}
				<button
					class="lm-chip"
					class:is-on-primary={hideIdle}
					title={hideIdle ? 'Show idle agents' : 'Hide idle agents'}
					onclick={() => (hideIdle = !hideIdle)}
				>
					{hideIdle ? 'Active only' : 'All agents'}
				</button>
			</div>
		</div>

		<div class="lm-panel lm-live" class:is-down={!eventStream.live}>
			<i></i>{eventStream.live ? 'Live' : 'Reconnecting'}
		</div>

		<div class="lm-panel lm-zoom">
			<button onclick={() => sim?.zoomBy(1 / 1.2)} title="Zoom out">−</button>
			<span>{zoom}%</span>
			<button onclick={() => sim?.zoomBy(1.2)} title="Zoom in">+</button>
			<button onclick={() => sim?.recenter()} title="Recenter and reset layout">⤢</button>
		</div>

		<div class="lm-panel lm-legend">
			<span><i style="background: var(--color-primary)"></i>In flight</span>
			<span><i style="background: var(--color-success)"></i>Completed</span>
			<span><i style="background: var(--color-warning)"></i>Awaiting approval</span>
			<span><i style="background: var(--color-danger)"></i>Denied</span>
		</div>

		{#if tip}
			<div class="lm-tip" style:left="{tip.x}px" style:top="{tip.y}px">
				<div class="lm-tip-id">{tip.node.label}</div>
				<div class="lm-tip-sub">{tipSubtitle(tip.node)}</div>
				<div class="lm-tip-rows">
					{#if tip.rows.length === 0}
						<div class="lm-tip-row is-muted">Idle</div>
					{/if}
					{#each tip.rows as row, i (i)}
						<div class="lm-tip-row" class:is-wait={row.waiting}>
							<i></i>{row.label}{row.waiting ? ' — in flight' : ''}
						</div>
					{/each}
					{#if tip.more > 0}
						<div class="lm-tip-row is-muted">+{tip.more} more</div>
					{/if}
				</div>
			</div>
		{/if}

		{#if identities.length === 0 && services.length === 0}
			<div class="lm-empty">Nothing to map yet — create an agent or a service.</div>
		{/if}
	</div>
</div>
