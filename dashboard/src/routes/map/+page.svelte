<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import '$lib/styles/livemap.css';
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

	// An agent created after the page loaded shows up in traffic before it
	// shows up in our snapshot. Refetch — throttled, because on a stale
	// snapshot *every* event from that agent asks, and the answer is the same.
	const REFETCH_COOLDOWN_MS = 15_000;
	let lastRefetch = 0;
	function refetchFleet() {
		const now = Date.now();
		if (now - lastRefetch < REFETCH_COOLDOWN_MS) return;
		lastRefetch = now;
		loadFleet().catch(() => {
			// Non-fatal: the map keeps running on the snapshot it has.
		});
	}
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
	<LiveMap {identities} {services} {currentUserId} {allowedDomains} onUnknownActor={refetchFleet} />
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
