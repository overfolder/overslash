<script lang="ts">
	import { goto } from '$app/navigation';
	import { session, ApiError } from '$lib/session';
	import AuditFiltersBar from './AuditFilters.svelte';
	import AuditRow from './AuditRow.svelte';
	import { downloadCsv } from './exportCsv';
	import {
		buildQuery,
		filtersToSearchString,
		PAGE_LIMIT,
		type AuditEntry,
		type AuditFilters
	} from './types';

	let { data } = $props();

	let entries = $state<AuditEntry[]>(data.entries);
	let filters = $state<AuditFilters>(data.filters);
	let offset = $state(data.entries.length);
	let done = $state(data.entries.length < PAGE_LIMIT);
	let loading = $state(false);
	let loadError = $state<string | null>(data.error?.message ?? null);
	let expandedId = $state<string | null>(null);

	let sentinel: HTMLDivElement | undefined = $state();

	async function fetchPage(reset: boolean) {
		if (loading) return;
		loading = true;
		loadError = null;
		const nextOffset = reset ? 0 : offset;
		try {
			const page = await session.get<AuditEntry[]>(
				`/v1/audit?${buildQuery(filters, PAGE_LIMIT, nextOffset)}`
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
			loadError =
				e instanceof ApiError ? `Failed to load audit log (${e.status}).` : 'Network error loading audit log.';
		} finally {
			loading = false;
		}
	}

	function applyFilters(next: AuditFilters) {
		filters = next;
		goto(`/audit${filtersToSearchString(next)}`, { keepFocus: true, noScroll: true, replaceState: true });
		fetchPage(true);
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

	<AuditFiltersBar {filters} onchange={applyFilters} />

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
