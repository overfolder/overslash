<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import type { ExecutionListItem } from '$lib/session';
	import { listExecutions, type ExecutionQuery } from '$lib/api/executions';
	import { eventStream, onEvent, EXECUTION_EVENT_TYPES } from '$lib/stores/events.svelte';
	import { formatTime } from '$lib/utils/time';

	let rows = $state<ExecutionListItem[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let scope = $state<'mine' | 'subtree'>('mine');
	let status = $state<string>('');

	// Events are notifications, not state: the payload deliberately carries no
	// result, so a handler that patched from it would render a half-row. Refetch.
	let refetchTimer: ReturnType<typeof setTimeout> | null = null;
	let generation = 0;

	async function load() {
		const mine = ++generation;
		const q: ExecutionQuery = { scope, limit: 100 };
		if (status) q.status = status;
		try {
			const next = await listExecutions(q);
			// Drop a stale response that lost the race to a newer one.
			if (mine !== generation) return;
			rows = next;
			error = null;
		} catch (e) {
			if (mine !== generation) return;
			error = e instanceof ApiError ? e.message : 'Failed to load executions';
		} finally {
			if (mine === generation) loading = false;
		}
	}

	function scheduleRefetch() {
		if (refetchTimer !== null) clearTimeout(refetchTimer);
		refetchTimer = setTimeout(() => {
			refetchTimer = null;
			void load();
		}, 300);
	}

	onMount(load);

	// `onEvent` returns its unsubscribe, so it must be the effect's return
	// value — calling it inside the body leaks a subscriber per re-run.
	$effect(() => onEvent([...EXECUTION_EVENT_TYPES, 'stream.resync'], scheduleRefetch));
	$effect(() => () => {
		if (refetchTimer !== null) clearTimeout(refetchTimer);
	});

	$effect(() => {
		// Re-read when the filters change.
		void scope;
		void status;
		void load();
	});

	const STATUSES = ['', 'pending', 'executing', 'executed', 'failed', 'cancelled', 'expired'];

	function pillClass(s: string): string {
		if (s === 'executed') return 'ok';
		if (s === 'failed' || s === 'expired') return 'bad';
		if (s === 'cancelled') return 'muted';
		return 'live';
	}
</script>

<div class="page">
	<header class="page-head">
		<div>
			<h1>Executions</h1>
			<p class="sub">
				Action calls that ran off the request path — anything started with
				<code>execution: "async"</code>, plus approved calls that were queued rather than run
				inline.
			</p>
		</div>
		<span class="live-pill" class:on={eventStream.live}>
			{eventStream.live ? 'Live' : 'Reconnecting…'}
		</span>
	</header>

	<div class="filters">
		<label>
			Scope
			<select bind:value={scope}>
				<option value="mine">Mine</option>
				<option value="subtree">My agents</option>
			</select>
		</label>
		<label>
			Status
			<select bind:value={status}>
				{#each STATUSES as s (s)}
					<option value={s}>{s === '' ? 'Any' : s}</option>
				{/each}
			</select>
		</label>
	</div>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if rows.length === 0}
		<div class="empty">
			<h2>No executions yet</h2>
			<p>
				A call made with <code>execution: "async"</code> is accepted immediately and runs in the
				background. A call made with <code>execution: "hybrid"</code> appears here too, once it
				runs long enough to leave the connection that started it.
			</p>
		</div>
	{:else}
		<div class="card">
			<table>
				<thead>
					<tr>
						<th>Status</th>
						<th>Service</th>
						<th>Origin</th>
						<th>Started</th>
						<th>Completed</th>
						<th class="chev-col"></th>
					</tr>
				</thead>
				<tbody>
					{#each rows as r (r.id)}
						<tr class="row" onclick={() => goto(`/executions/${r.id}`)}>
							<td>
								<span class="pill {pillClass(r.status)}">{r.status}</span>
								{#if r.cancel_requested && r.status === 'executing'}
									<span class="pill muted">cancelling</span>
								{/if}
							</td>
							<td><span class="mono">{r.service ?? '—'}</span></td>
							<td class="muted-text"
							>{r.origin === 'approval'
								? 'Approved'
								: r.origin === 'hybrid'
									? 'Handed off'
									: 'Direct'}</td
						>
							<td class="muted-text">{r.started_at ? formatTime(r.started_at) : '—'}</td>
							<td class="muted-text">{r.completed_at ? formatTime(r.completed_at) : '—'}</td>
							<td class="chev">›</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

<style>
	.page {
		max-width: 1100px;
	}
	.page-head {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 20px;
	}
	h1 {
		font: var(--text-h1);
		margin: 0;
		color: var(--color-text-heading);
	}
	.sub {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		margin: 2px 0 0;
		max-width: 62ch;
	}
	.live-pill {
		font: var(--text-label);
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: 999px;
		padding: 3px 10px;
		white-space: nowrap;
	}
	.live-pill.on {
		color: var(--color-success, #1a7f37);
		border-color: currentColor;
	}
	.filters {
		display: flex;
		gap: 16px;
		margin-bottom: 16px;
	}
	.filters label {
		font: var(--text-label);
		color: var(--color-text-muted);
		display: flex;
		align-items: center;
		gap: 6px;
	}
	.filters select {
		font: var(--text-body-sm);
		padding: 5px 8px;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
		color: var(--color-text);
	}
	.error {
		background: rgba(229, 56, 54, 0.06);
		border: 1px solid rgba(229, 56, 54, 0.2);
		color: var(--color-danger);
		border-radius: 8px;
		padding: 10px 12px;
		margin-bottom: 16px;
		font-size: 13px;
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 40px 24px;
		text-align: center;
		color: var(--color-text-muted);
	}
	.empty h2 {
		margin: 0 0 8px;
		color: var(--color-text-heading);
		font-size: 16px;
	}
	.empty p {
		margin: 0;
		font-size: 13px;
		max-width: 52ch;
		margin-inline: auto;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		overflow: hidden;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font: var(--text-body);
	}
	th {
		text-align: left;
		font-size: 11px;
		font-weight: 500;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--color-text-muted);
		padding: 10px 14px;
		border-bottom: 1px solid var(--color-border);
		background: var(--color-sidebar);
	}
	td {
		padding: 12px 14px;
		border-bottom: 1px solid var(--color-border-subtle);
		vertical-align: middle;
	}
	.row {
		cursor: pointer;
	}
	.row:hover {
		background: var(--color-surface-hover, rgba(0, 0, 0, 0.02));
	}
	.mono {
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 12px;
	}
	.muted-text {
		color: var(--color-text-muted);
		font-size: 12px;
	}
	.pill {
		display: inline-block;
		border-radius: 999px;
		padding: 2px 9px;
		font-size: 11px;
		border: 1px solid var(--color-border);
		color: var(--color-text-muted);
	}
	.pill.ok {
		color: var(--color-success, #1a7f37);
		border-color: currentColor;
	}
	.pill.bad {
		color: var(--color-danger);
		border-color: currentColor;
	}
	.pill.live {
		color: var(--color-primary);
		border-color: currentColor;
	}
	.chev-col {
		width: 28px;
	}
	.chev {
		color: var(--color-text-muted);
		text-align: right;
	}
</style>
