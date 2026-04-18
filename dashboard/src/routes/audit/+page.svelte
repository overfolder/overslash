<script lang="ts">
	import { replaceState } from '$app/navigation';
	import { session, ApiError } from '$lib/session';
	import SearchBar, { type SearchValue } from '$lib/components/SearchBar.svelte';
	import AuditRow from './AuditRow.svelte';
	import { downloadCsv } from './exportCsv';
	import { buildAuditSearchKeys, filtersToSearch, searchToFilters } from './searchMapping';
	import {
		buildQuery,
		filtersToSearchString,
		PAGE_LIMIT,
		type AuditEntry,
		type AuditFilters
	} from './types';

	let { data } = $props();

	// svelte-ignore state_referenced_locally
	let entries = $state<AuditEntry[]>(data.entries);
	// svelte-ignore state_referenced_locally
	let filters = $state<AuditFilters>(data.filters);
	// svelte-ignore state_referenced_locally
	const identities = data.identities;
	const searchKeys = buildAuditSearchKeys(identities);
	// svelte-ignore state_referenced_locally
	let searchValue = $state<SearchValue>(filtersToSearch(data.filters, identities));
	// svelte-ignore state_referenced_locally
	let offset = $state(data.entries.length);
	// svelte-ignore state_referenced_locally
	let done = $state(data.entries.length < PAGE_LIMIT);
	let loading = $state(false);
	// svelte-ignore state_referenced_locally
	let loadError = $state<string | null>(data.error?.message ?? null);
	let expandedId = $state<string | null>(null);

	let sentinel: HTMLDivElement | undefined = $state();
	// Tracks the in-flight audit fetch so a filter change can cancel any
	// scroll-triggered request that would otherwise overwrite the new page
	// with stale data.
	let inFlight: AbortController | null = null;

	async function fetchPage(reset: boolean) {
		// On reset (filter change / refresh) abort any pending scroll fetch
		// so its response can't clobber the freshly-filtered page.
		if (reset && inFlight) {
			inFlight.abort();
			inFlight = null;
		} else if (loading) {
			return;
		}
		const ctrl = new AbortController();
		inFlight = ctrl;
		loading = true;
		loadError = null;
		const nextOffset = reset ? 0 : offset;
		const requestFilters = filters;
		try {
			const page = await session.get<AuditEntry[]>(
				`/v1/audit?${buildQuery(requestFilters, PAGE_LIMIT, nextOffset)}`,
				ctrl.signal
			);
			if (reset) {
				entries = page;
				offset = page.length;
			} else {
				entries = [...entries, ...page];
				offset += page.length;
			}
			done = page.length < PAGE_LIMIT;
		} catch (e) {
			if ((e as { name?: string })?.name === 'AbortError') return;
			loadError =
				e instanceof ApiError ? `Failed to load audit log (${e.status}).` : 'Network error loading audit log.';
		} finally {
			if (inFlight === ctrl) {
				inFlight = null;
				loading = false;
			}
		}
	}

	function applyFilters(next: AuditFilters) {
		filters = next;
		// Update the URL in place so filters are shareable, without re-running
		// the page `load` function (which would duplicate the network request
		// triggered by fetchPage below).
		replaceState(`/audit${filtersToSearchString(next)}`, {});
		fetchPage(true);
	}

	function onSearchChange(next: SearchValue) {
		searchValue = next;
		applyFilters(searchToFilters(next, identities));
	}

	function refresh() {
		fetchPage(true);
	}

	function toggleExpand(id: string) {
		expandedId = expandedId === id ? null : id;
	}

	$effect(() => {
		if (!sentinel) return;
		const obs = new IntersectionObserver(
			(items) => {
				if (items.some((i) => i.isIntersecting) && !loading && !done && !loadError) {
					fetchPage(false);
				}
			},
			{ rootMargin: '200px' }
		);
		obs.observe(sentinel);
		return () => obs.disconnect();
	});
</script>

<svelte:head>
	<title>Audit Log · Overslash</title>
</svelte:head>

<div class="page">
	<header class="header">
		<h1>Audit Log</h1>
		<div class="actions">
			<button type="button" onclick={refresh} disabled={loading}>Refresh</button>
			<button type="button" onclick={() => downloadCsv(entries)} disabled={entries.length === 0}>
				Export CSV
			</button>
		</div>
	</header>

	<div class="search-wrap">
		<SearchBar
			keys={searchKeys}
			value={searchValue}
			onchange={onSearchChange}
			placeholder="Search audit log — try `event = action.executed` or free text"
		/>
	</div>

	{#if loadError && entries.length === 0}
		<div class="state error">
			{loadError}
			<button type="button" onclick={refresh}>Retry</button>
		</div>
	{:else if entries.length === 0 && !loading}
		<div class="state muted">No audit events match the current filters.</div>
	{:else}
		<div class="table-wrap">
			<table>
				<thead>
					<tr>
						<th>Timestamp</th>
						<th>Identity</th>
						<th>Event</th>
						<th>Resource</th>
						<th>Description</th>
						<th>IP</th>
					</tr>
				</thead>
				<tbody>
					{#each entries as entry (entry.id)}
						<AuditRow
							{entry}
							expanded={expandedId === entry.id}
							ontoggle={() => toggleExpand(entry.id)}
						/>
					{/each}
				</tbody>
			</table>
		</div>

		{#if loading}
			<div class="state muted">Loading more…</div>
		{:else if loadError}
			<div class="state error">
				{loadError}
				<button type="button" onclick={() => fetchPage(false)}>Retry</button>
			</div>
		{:else if done}
			<div class="state muted">No more events.</div>
		{/if}
		<div bind:this={sentinel} class="sentinel"></div>
	{/if}
</div>

<style>
	.page {
		padding: var(--space-6, 24px);
		max-width: 1400px;
		margin: 0 auto;
	}
	.header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: var(--space-4);
	}
	.header h1 {
		margin: 0;
		font-size: var(--text-h1, 1.5rem);
	}
	.actions {
		display: flex;
		gap: var(--space-2);
	}
	.search-wrap {
		margin-bottom: var(--space-4);
	}
	.actions button {
		padding: 6px 12px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		border-radius: var(--radius-sm, 4px);
		cursor: pointer;
	}
	.actions button:hover:not(:disabled) {
		border-color: var(--color-primary);
	}
	.actions button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.table-wrap {
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md, 8px);
		overflow: auto;
		background: var(--color-bg);
	}
	table {
		width: 100%;
		border-collapse: collapse;
	}
	thead th {
		position: sticky;
		top: 0;
		text-align: left;
		padding: var(--space-3) var(--space-4);
		background: var(--color-bg-elevated);
		border-bottom: 1px solid var(--color-border);
		font-size: var(--text-label, 0.75rem);
		text-transform: uppercase;
		color: var(--color-text-muted);
		font-weight: 600;
	}
	.state {
		padding: var(--space-4);
		text-align: center;
	}
	.state.muted {
		color: var(--color-text-muted);
	}
	.state.error {
		color: var(--color-error, #c33);
	}
	.state button {
		margin-left: var(--space-2);
		padding: 4px 10px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		border-radius: var(--radius-sm, 4px);
		cursor: pointer;
	}
	.sentinel {
		height: 1px;
	}
</style>
