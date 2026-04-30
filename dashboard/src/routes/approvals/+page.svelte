<script lang="ts">
	import ApprovalResolver from '$lib/components/ApprovalResolver.svelte';
	import IdentityPath from '$lib/components/IdentityPath.svelte';
	import { session, type ApprovalResponse } from '$lib/session';
	import { relativeTime as relativeTimeUtil } from '$lib/utils/time';
	import { onMount } from 'svelte';

	let {
		data
	}: {
		data: {
			approvals: ApprovalResponse[];
			pendingExecutions: ApprovalResponse[];
			error: string | null;
		};
	} = $props();

	let approvals = $state<ApprovalResponse[]>([]);
	let pendingExecutions = $state<ApprovalResponse[]>([]);
	let expandedId = $state<string | null>(null);
	let execBusy = $state<Record<string, boolean>>({});
	let execError = $state<string | null>(null);

	$effect(() => {
		approvals = data.approvals;
	});
	$effect(() => {
		pendingExecutions = data.pendingExecutions.filter(
			(a) => a.execution?.status === 'pending'
		);
	});

	// Tick state to drive periodic re-render of relativeTime() output.
	let tick = $state(0);

	onMount(() => {
		const id = setInterval(() => (tick += 1), 30_000);
		return () => clearInterval(id);
	});

	function relativeTime(iso: string): string {
		// Reference `tick` so this re-runs on the interval above.
		void tick;
		return relativeTimeUtil(iso);
	}

	function primaryKey(a: ApprovalResponse): string {
		const k = a.derived_keys[0];
		return k ? `${k.service}:${k.action}` : '—';
	}

	function toggle(id: string) {
		expandedId = expandedId === id ? null : id;
	}

	function handleResolved(updated: ApprovalResponse) {
		if (updated.status !== 'pending') {
			const cascaded = new Set(updated.cascaded_approval_ids ?? []);
			approvals = approvals.filter((a) => a.id !== updated.id && !cascaded.has(a.id));
			if (expandedId === updated.id) expandedId = null;
			if (expandedId && cascaded.has(expandedId)) expandedId = null;
		}
	}

	function hasBubbled(a: ApprovalResponse): boolean {
		return (
			!!a.current_resolver_identity_id &&
			a.current_resolver_identity_id !== a.requesting_identity_id
		);
	}

	async function callExecution(a: ApprovalResponse) {
		execBusy = { ...execBusy, [a.id]: true };
		execError = null;
		try {
			await session.post(`/v1/approvals/${a.id}/call`);
			pendingExecutions = pendingExecutions.filter((x) => x.id !== a.id);
		} catch (e) {
			execError = e instanceof Error ? e.message : 'Failed to dispatch execution.';
		} finally {
			execBusy = { ...execBusy, [a.id]: false };
		}
	}

	async function cancelExecution(a: ApprovalResponse) {
		execBusy = { ...execBusy, [a.id]: true };
		execError = null;
		try {
			await session.post(`/v1/approvals/${a.id}/cancel`);
			pendingExecutions = pendingExecutions.filter((x) => x.id !== a.id);
		} catch (e) {
			execError = e instanceof Error ? e.message : 'Failed to cancel execution.';
		} finally {
			execBusy = { ...execBusy, [a.id]: false };
		}
	}
</script>

<div class="page">
	<header class="header">
		<h1>Approvals</h1>
		<span class="count">{approvals.length} pending</span>
	</header>

	{#if data.error}
		<div class="banner banner-error">{data.error}</div>
	{:else if approvals.length === 0}
		<div class="empty">No approvals waiting for you.</div>
	{:else}
		<ul class="list">
			{#each approvals as a (a.id)}
				<li class="row" class:expanded={expandedId === a.id}>
					<button class="row-summary" onclick={() => toggle(a.id)}>
						<div class="col col-identity">
							{#if a.identity_path}
								<IdentityPath path={a.identity_path} pathIds={a.identity_path_ids} />
							{:else}
								<code class="mono mute">{a.requesting_identity_id}</code>
							{/if}
							{#if hasBubbled(a)}
								<span class="tag-bubbled">bubbled</span>
							{/if}
						</div>
						<div class="col col-summary">{a.action_summary}</div>
						<div class="col col-key"><code class="mono">{primaryKey(a)}</code></div>
						<div class="col col-time">
							<div>{relativeTime(a.created_at)}</div>
							<div class="mute small">expires {relativeTime(a.expires_at)}</div>
						</div>
					</button>
					{#if expandedId === a.id}
						<div class="row-body">
							<ApprovalResolver approval={a} compact onResolved={handleResolved} />
						</div>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}

	{#if pendingExecutions.length > 0}
		<section class="exec-section">
			<header class="exec-header">
				<h2>Pending Executions</h2>
				<span class="count">{pendingExecutions.length} ready</span>
			</header>
			{#if execError}
				<div class="banner banner-error">{execError}</div>
			{/if}
			<ul class="list">
				{#each pendingExecutions as a (a.id)}
					<li class="row exec-row">
						<div class="exec-body">
							<div class="exec-main">
								<div class="col col-identity">
									{#if a.identity_path}
										<IdentityPath path={a.identity_path} pathIds={a.identity_path_ids} />
									{:else}
										<code class="mono mute">{a.requesting_identity_id}</code>
									{/if}
								</div>
								<div class="col col-summary">{a.action_summary}</div>
								<div class="col col-key"><code class="mono">{primaryKey(a)}</code></div>
								<div class="col col-time">
									<div class="mute small">
										expires {relativeTime(a.execution?.expires_at ?? a.expires_at)}
									</div>
								</div>
							</div>
							<div class="exec-actions">
								<button
									class="btn btn-call"
									disabled={execBusy[a.id]}
									onclick={() => callExecution(a)}
								>
									{execBusy[a.id] ? 'Calling…' : 'Call now'}
								</button>
								<button
									class="btn btn-cancel"
									disabled={execBusy[a.id]}
									onclick={() => cancelExecution(a)}
								>
									Cancel
								</button>
							</div>
						</div>
					</li>
				{/each}
			</ul>
		</section>
	{/if}
</div>

<style>
	.page {
		padding: 1.5rem 2rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 1100px;
	}
	.header {
		display: flex;
		align-items: baseline;
		gap: 0.75rem;
	}
	h1 {
		margin: 0;
		font-size: 1.4rem;
		font-weight: 700;
		color: var(--color-text);
	}
	.count {
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
	.empty {
		padding: 2rem;
		text-align: center;
		color: var(--color-text-muted);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
	}
	.banner-error {
		padding: 0.75rem 1rem;
		border: 1px solid #d14343;
		background: rgba(209, 67, 67, 0.06);
		color: #d14343;
		border-radius: 8px;
		font-size: 0.85rem;
	}
	.list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}
	.row {
		background: var(--color-surface, #fafafa);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		overflow: hidden;
	}
	.row.expanded {
		background: #fff;
	}
	.row-summary {
		display: grid;
		grid-template-columns: minmax(0, 1.4fr) minmax(0, 2fr) minmax(0, 1.2fr) auto;
		gap: 1rem;
		align-items: center;
		width: 100%;
		padding: 0.85rem 1rem;
		background: transparent;
		border: none;
		text-align: left;
		cursor: pointer;
		font: inherit;
		color: inherit;
	}
	.row-summary:hover {
		background: rgba(0, 0, 0, 0.02);
	}
	.col {
		min-width: 0;
	}
	.col-summary {
		font-weight: 500;
		color: var(--color-text);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.col-time {
		text-align: right;
		font-size: 0.8rem;
		color: var(--color-text);
	}
	.col-identity {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}
	.tag-bubbled {
		font-size: 0.7rem;
		padding: 0.1rem 0.4rem;
		border-radius: 999px;
		background: #fff3e0;
		color: #b35900;
		border: 1px solid #ffd699;
	}
	.row-body {
		padding: 0 1rem 1rem 1rem;
		border-top: 1px solid var(--color-border);
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.78rem;
	}
	.mute {
		color: var(--color-text-muted);
	}
	.small {
		font-size: 0.72rem;
	}

	/* Pending Executions section */
	.exec-section {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.exec-header {
		display: flex;
		align-items: baseline;
		gap: 0.75rem;
	}
	h2 {
		margin: 0;
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text);
	}
	.exec-row {
		background: #fffbf0;
		border-color: #f5d87a;
	}
	.exec-body {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 0.85rem 1rem;
	}
	.exec-main {
		display: grid;
		grid-template-columns: minmax(0, 1.4fr) minmax(0, 2fr) minmax(0, 1.2fr) auto;
		gap: 1rem;
		align-items: center;
		flex: 1;
		min-width: 0;
	}
	.exec-actions {
		display: flex;
		gap: 0.5rem;
		flex-shrink: 0;
	}
	.btn {
		padding: 0.35rem 0.85rem;
		border-radius: var(--radius-sm, 4px);
		border: 1px solid transparent;
		font-size: 0.8rem;
		font-weight: 500;
		cursor: pointer;
		white-space: nowrap;
	}
	.btn:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}
	.btn-call {
		background: var(--color-primary, #6366f1);
		color: #fff;
		border-color: var(--color-primary, #6366f1);
	}
	.btn-call:not(:disabled):hover {
		background: var(--color-primary-hover, #4f46e5);
		border-color: var(--color-primary-hover, #4f46e5);
	}
	.btn-cancel {
		background: transparent;
		color: var(--color-text-muted);
		border-color: var(--color-border);
	}
	.btn-cancel:not(:disabled):hover {
		color: #d14343;
		border-color: #d14343;
	}
</style>
