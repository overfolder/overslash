<script lang="ts">
	import { replaceState } from '$app/navigation';
	import { tick } from 'svelte';
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
	// Deep-link: `?event=<uuid>` selects an event to expand. If that event is
	// already in the visible page we just scroll-and-expand; if it's outside
	// the current filter set we keep the anchor row pinned above the table.
	// svelte-ignore state_referenced_locally
	let eventId = $state<string | null>(data.eventId);
	// svelte-ignore state_referenced_locally
	let anchor = $state<AuditEntry | null>(data.anchor);
	// svelte-ignore state_referenced_locally
	let expandedId = $state<string | null>(eventId);

	let sentinel: HTMLDivElement | undefined = $state();
	let tableWrap: HTMLDivElement | undefined = $state();
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

	function buildUrl(next: AuditFilters): string {
		const base = `/audit${filtersToSearchString(next)}`;
		// Preserve `?event=<uuid>` across filter changes when the anchor is
		// still useful — i.e. the targeted event still exists. Drop it when
		// the user has explicitly cleared the deep-link via the anchor's
		// "Clear" affordance.
		if (!eventId) return base;
		const sep = base.includes('?') ? '&' : '?';
		return `${base}${sep}event=${eventId}`;
	}

	function applyFilters(next: AuditFilters) {
		filters = next;
		// Update the URL in place so filters are shareable, without re-running
		// the page `load` function (which would duplicate the network request
		// triggered by fetchPage below).
		replaceState(buildUrl(next), {});
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

	function clearAnchor() {
		eventId = null;
		anchor = null;
		expandedId = null;
		replaceState(`/audit${filtersToSearchString(filters)}`, {});
	}

	async function scrollToEvent(id: string) {
		await tick();
		const el = tableWrap?.querySelector<HTMLTableRowElement>(`tr[data-event-id="${id}"]`);
		if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
	}

	// Suppress the anchor row when the deep-linked event is already in the
	// filtered list — rendering it twice would be confusing. We still keep
	// `anchor` in state so toggling filters can re-evaluate.
	const anchorVisible = $derived(
		!!anchor && !entries.some((e) => e.id === anchor!.id)
	);

	$effect(() => {
		if (eventId) scrollToEvent(eventId);
	});

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

	{#if anchorVisible && anchor}
		<div class="anchor-wrap" data-test="audit-anchor">
			<div class="anchor-banner">
				<span>Anchored to event <code class="mono">{anchor.id}</code> — outside the current filters.</span>
				<button type="button" onclick={clearAnchor}>Clear</button>
			</div>
			<div class="table-wrap anchor-table">
				<table>
					<tbody>
						<AuditRow
							entry={anchor}
							expanded={expandedId === anchor.id}
							ontoggle={() => toggleExpand(anchor!.id)}
						/>
					</tbody>
				</table>
			</div>
		</div>
	{/if}

	{#if loadError && entries.length === 0}
		<div class="state error">
			{loadError}
			<button type="button" onclick={refresh}>Retry</button>
		</div>
	{:else if entries.length === 0 && !loading}
		<div class="state muted">No audit events match the current filters.</div>
	{:else}
		<div class="table-wrap" bind:this={tableWrap}>
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
						<svelte:boundary>
							<AuditRow
								{entry}
								expanded={expandedId === entry.id}
								ontoggle={() => toggleExpand(entry.id)}
							/>
							{#snippet failed(error)}
								<tr>
									<td colspan="6" class="muted">
										Failed to render entry {entry.id}: {String(
											(error as { message?: string })?.message ?? error
										)}
									</td>
								</tr>
							{/snippet}
						</svelte:boundary>
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
	.anchor-wrap {
		margin-bottom: var(--space-4);
	}
	.anchor-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border);
		border-bottom: none;
		border-top-left-radius: var(--radius-md, 8px);
		border-top-right-radius: var(--radius-md, 8px);
		background: color-mix(in srgb, var(--color-primary, #3b82f6) 8%, transparent);
		font-size: 0.85rem;
	}
	.anchor-banner button {
		padding: 4px 10px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		border-radius: var(--radius-sm, 4px);
		cursor: pointer;
	}
	.anchor-table {
		border-top-left-radius: 0;
		border-top-right-radius: 0;
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
</style>
