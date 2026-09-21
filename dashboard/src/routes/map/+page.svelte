<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { page } from '$app/stores';
	import '$lib/styles/livemap.css';
	import { onEvent, SERVICE_EVENT_TYPES } from '$lib/stores/events.svelte';
	import { listIdentities } from '$lib/identityApi';
	import { listServices } from '$lib/api/services';
	import { getVersion } from '$lib/api/version';
	import LiveMap from '$lib/components/map/LiveMap.svelte';
	import type { Identity, ServiceInstanceSummary } from '$lib/types';

	// Supplied by the root layout load, same as the services list reads them:
	// the map's service tooltips name an owner through `$lib/ownerLabel`, which
	// wants the viewer's own id and the org's sign-in domains to say "Yours"
	// and to strip `@acme.com` off everyone else's.
	const currentUserId = $derived(($page as any).data?.user?.identity_id as string | undefined);
	const allowedDomains = $derived((($page as any).data?.allowedDomains ?? []) as string[]);

	let identities = $state<Identity[]>([]);
	let services = $state<ServiceInstanceSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	/** `null` until `/v1/version` answers — the page must not accuse a build of
	 *  lacking the feature before it has been asked. */
	let enabled = $state<boolean | null>(null);

	async function loadFleet() {
		const [ids, svcs] = await Promise.all([
			listIdentities(),
			listServices({ includeUserLevel: true })
		]);
		// Archived identities are history, not fleet.
		identities = ids.filter((i) => !i.archived_at);
		services = svcs;
	}

	onMount(async () => {
		try {
			const [version] = await Promise.all([getVersion(), loadFleet()]);
			enabled = version.live_map === true;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load the map';
		} finally {
			loading = false;
		}
	});

	// An agent or a service created after the page loaded is absent from our
	// snapshot. Refetch — throttled, because on a stale snapshot *every* event
	// naming it asks, and the answer is the same.
	//
	// Trailing edge, not leading: an ask inside the cooldown is deferred to the
	// end of it rather than dropped. Dropping is what a rate limiter does to
	// traffic it can afford to lose, and this is the opposite — the ask is a
	// one-shot signal that the snapshot is wrong, and swallowing it leaves the
	// map stale until the next unrelated event happens to ask again.
	const REFETCH_COOLDOWN_MS = 15_000;
	let lastRefetch = 0;
	let deferred: ReturnType<typeof setTimeout> | null = null;

	function refetchFleet() {
		if (deferred) return;
		const wait = REFETCH_COOLDOWN_MS - (Date.now() - lastRefetch);
		if (wait > 0) {
			deferred = setTimeout(() => {
				deferred = null;
				refetchFleet();
			}, wait);
			return;
		}
		lastRefetch = Date.now();
		loadFleet().catch(() => {
			// Non-fatal: the map keeps running on the snapshot it has.
		});
	}

	// The fleet itself changed. `service.*` is a notification, not a rendering —
	// the payload names the instance and stops there, and everything the map
	// draws a service with (its owner, its icon) comes from the listing. So the
	// handler refetches rather than patching a node together from the event.
	//
	// `stream.resync` joins them because it means "you may have missed events",
	// and a missed `service.created` looks exactly like no service at all.
	onMount(() =>
		onEvent([...SERVICE_EVENT_TYPES, 'stream.resync'], () => refetchFleet())
	);

	onDestroy(() => {
		if (deferred) clearTimeout(deferred);
	});
</script>

<svelte:head><title>Live Map · Overslash</title></svelte:head>

{#if loading}
	<div class="state">Loading the fleet…</div>
{:else if error}
	<div class="state">{error}</div>
{:else if enabled === false}
	<div class="state">
		<p>The Live Map is off on this deployment.</p>
		<p class="hint">
			It needs <code>OVERSLASH_LIVE_MAP</code> on the API, which emits the per-call
			<code>action.*</code> events the map animates. Without them the graph would never move.
		</p>
	</div>
{:else}
	<LiveMap {identities} {services} {currentUserId} {allowedDomains} onStaleFleet={refetchFleet} />
{/if}

<style>
	.state {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		padding: 2rem;
		text-align: center;
		color: var(--color-text-muted);
	}
	.hint {
		max-width: 32rem;
		font: var(--text-body-sm);
	}
	code {
		font-family: var(--font-mono);
		font-size: 0.85em;
		color: var(--color-text-secondary);
	}
</style>
