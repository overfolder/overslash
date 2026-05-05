<script lang="ts">
	import ApprovalResolver from '$lib/components/ApprovalResolver.svelte';
	import IdentityPath from '$lib/components/IdentityPath.svelte';
	import RiskDot from '$lib/components/approval/RiskDot.svelte';
	import ServiceTile from '$lib/components/approval/ServiceTile.svelte';
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
		pendingExecutions = data.pendingExecutions.filter((a) => {
			const s = a.execution?.status;
			if (s === 'pending') return true;
			// "Called but output unread": auto-call (or any prior /call) ran the
			// action to a terminal state, but the agent hasn't read the result
			// yet. Surface so the operator sees the outcome and the HTTP code
			// without having to click into the agent.
			if ((s === 'executed' || s === 'failed') && a.execution?.output_read === false) {
				return true;
			}
			return false;
		});
	});

	function executionStateLabel(a: ApprovalResponse): 'pending' | 'executed' | 'failed' {
		const s = a.execution?.status;
		if (s === 'executed') return 'executed';
		if (s === 'failed') return 'failed';
		return 'pending';
	}

	let tick = $state(0);
	onMount(() => {
		const id = setInterval(() => (tick += 1), 30_000);
		return () => clearInterval(id);
	});

	function relativeTime(iso: string): string {
		void tick;
		return relativeTimeUtil(iso);
	}

	function primaryService(a: ApprovalResponse): string {
		return a.derived_keys[0]?.service ?? 'unknown';
	}

	function primaryArg(a: ApprovalResponse): string {
		return a.derived_keys[0]?.arg ?? '*';
	}

	function agentName(a: ApprovalResponse): string {
		if (a.identity_path) {
			const parts = a.identity_path.replace(/^spiffe:\/\//, '').split('/');
			const last = parts[parts.length - 1];
			if (last) return last;
		}
		return a.requesting_identity_id.slice(0, 8);
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
	<header class="page-head">
		<div>
			<h1>Approvals</h1>
			<p class="sub">{approvals.length} pending</p>
		</div>
	</header>

	{#if data.error}
		<div class="banner banner-error">{data.error}</div>
	{:else if approvals.length === 0}
		<div class="empty">No approvals waiting for you.</div>
	{:else}
		<div class="legend">
			<span><RiskDot risk="low" size={6} /> Low risk</span>
			<span><RiskDot risk="med" size={6} /> Medium risk</span>
			<span><RiskDot risk="high" size={6} /> High risk</span>
		</div>

		<ul class="list">
			{#each approvals as a (a.id)}
				<li class="row" class:expanded={expandedId === a.id}>
					<button class="row-summary" onclick={() => toggle(a.id)}>
						<RiskDot risk={a.risk} />
						<ServiceTile name={primaryService(a)} />
						<div class="row-text">
							<span class="row-title">
								<span class="action">{a.action_summary}</span>
								<span class="dot-sep">·</span>
								<code class="mono">{agentName(a)}</code>
								<span class="muted"> on </span>
								<code class="mono">{primaryArg(a)}</code>
							</span>
							{#if hasBubbled(a)}
								<span class="tag-bubbled">bubbled</span>
							{/if}
						</div>
						<span class="row-time mono">{relativeTime(a.created_at)}</span>
						<span class="row-caret" class:open={expandedId === a.id}>▶</span>
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
			<header class="exec-head">
				<h2>Pending calls</h2>
				<span class="count">{pendingExecutions.length} pending</span>
			</header>
			{#if execError}
				<div class="banner banner-error">{execError}</div>
			{/if}
			<ul class="list">
				{#each pendingExecutions as a (a.id)}
					{@const state = executionStateLabel(a)}
					<li class="row exec-row exec-row--{state}">
						<div class="exec-row-body">
							<RiskDot risk={a.risk} />
							<ServiceTile name={primaryService(a)} />
							<div class="row-text">
								<span class="row-title">
									<span class="action">{a.action_summary}</span>
									<span class="dot-sep">·</span>
									{#if a.identity_path}
										<IdentityPath path={a.identity_path} pathIds={a.identity_path_ids} />
									{:else}
										<code class="mono muted">{agentName(a)}</code>
									{/if}
								</span>
							</div>
							<div class="exec-status">
								{#if state === 'pending'}
									<span class="exec-pill exec-pill--pending">awaiting call</span>
								{:else if state === 'executed'}
									<span class="exec-pill exec-pill--executed">called</span>
									{#if a.execution?.http_status_code != null}
										<code class="mono small muted">{a.execution.http_status_code}</code>
									{/if}
									{#if a.execution?.triggered_by === 'auto'}
										<span class="exec-trigger">auto</span>
									{/if}
								{:else}
									<span class="exec-pill exec-pill--failed">failed</span>
									{#if a.execution?.http_status_code != null}
										<code class="mono small muted">{a.execution.http_status_code}</code>
									{/if}
									{#if a.execution?.error}
										<span class="exec-error muted small" title={a.execution.error}>
											{a.execution.error.slice(0, 64)}
										</span>
									{/if}
								{/if}
							</div>
							<div class="row-time">
								{#if state === 'pending'}
									<div class="muted small">
										expires {relativeTime(a.execution?.expires_at ?? a.expires_at)}
									</div>
								{:else if a.execution?.completed_at}
									<div class="muted small">
										completed {relativeTime(a.execution.completed_at)}
									</div>
								{/if}
								{#if state !== 'pending'}
									<div class="muted small">awaiting agent read</div>
								{/if}
							</div>
							{#if state === 'pending'}
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
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		</section>
	{/if}
</div>

<style>
	.page {
		padding: 24px 32px;
		display: flex;
		flex-direction: column;
		gap: 16px;
		max-width: 1100px;
		width: 100%;
	}
	.page-head {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		gap: 16px;
	}
	h1 {
		margin: 0;
		font: var(--text-h1);
		color: var(--color-text-heading);
	}
	.sub {
		margin: 2px 0 0;
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}

	.legend {
		display: flex;
		gap: 16px;
		font-size: 11px;
		color: var(--color-text-muted);
	}
	.legend span {
		display: inline-flex;
		align-items: center;
		gap: 5px;
	}

	.empty {
		padding: 32px;
		text-align: center;
		color: var(--color-text-muted);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
	}
	.banner-error {
		padding: 10px 14px;
		border: 1px solid var(--color-danger);
		background: var(--badge-bg-danger);
		color: var(--color-danger);
		border-radius: 8px;
		font-size: 13px;
	}

	.list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.row {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		overflow: hidden;
		transition: border-color 0.1s;
	}
	.row.expanded {
		border-color: var(--color-primary);
	}
	.row-summary {
		display: grid;
		grid-template-columns: 8px 28px 1fr auto auto;
		gap: 12px;
		align-items: center;
		width: 100%;
		padding: 12px 14px;
		background: transparent;
		border: 0;
		text-align: left;
		cursor: pointer;
		font: inherit;
		color: inherit;
	}
	.row-summary:hover {
		background: var(--color-sidebar);
	}
	.row-text {
		min-width: 0;
		display: flex;
		align-items: center;
		gap: 8px;
	}
	.row-title {
		display: inline-flex;
		align-items: baseline;
		gap: 4px;
		min-width: 0;
		font-size: 13px;
		color: var(--color-text);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.action {
		font-weight: 500;
	}
	.dot-sep {
		color: var(--color-text-muted);
		padding: 0 2px;
	}
	.row-time {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.row-caret {
		font-size: 10px;
		color: var(--color-text-muted);
		transition: transform 0.15s;
	}
	.row-caret.open {
		transform: rotate(90deg);
	}

	.tag-bubbled {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: 9999px;
		background: var(--badge-bg-warning);
		color: var(--color-warning);
		flex: none;
	}

	.row-body {
		padding: 12px 14px 14px;
		border-top: 1px solid var(--color-border-subtle);
		background: var(--color-sidebar);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-text);
	}
	.muted {
		color: var(--color-text-muted);
	}
	.small {
		font-size: 11px;
	}

	/* === Pending calls === */
	.exec-section {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}
	.exec-head {
		display: flex;
		align-items: baseline;
		gap: 12px;
	}
	h2 {
		margin: 0;
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.count {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.exec-row {
		border-color: rgba(235, 176, 31, 0.4);
		background: var(--badge-bg-warning);
	}
	.exec-row--executed {
		border-color: rgba(33, 184, 107, 0.4);
		background: var(--badge-bg-success);
	}
	.exec-row--failed {
		border-color: rgba(229, 56, 54, 0.4);
		background: var(--badge-bg-danger);
	}
	.exec-row-body {
		display: grid;
		grid-template-columns: 8px 28px minmax(0, 1.4fr) minmax(0, 1fr) minmax(0, 1.2fr) auto;
		gap: 12px;
		align-items: center;
		padding: 12px 14px;
	}
	.exec-status {
		display: flex;
		align-items: center;
		gap: 6px;
		flex-wrap: wrap;
		min-width: 0;
	}
	.exec-pill {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.02em;
	}
	.exec-pill--pending {
		background: var(--badge-bg-warning);
		color: var(--color-warning);
	}
	.exec-pill--executed {
		background: var(--badge-bg-success);
		color: var(--color-success);
	}
	.exec-pill--failed {
		background: var(--badge-bg-danger);
		color: var(--color-danger);
	}
	.exec-trigger {
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		padding: 1px 6px;
		border-radius: 3px;
		background: var(--color-sidebar);
	}
	.exec-error {
		max-width: 16rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.exec-actions {
		display: flex;
		gap: 6px;
		flex-shrink: 0;
	}
	.btn {
		padding: 6px 12px;
		border-radius: 6px;
		border: 1px solid transparent;
		font-size: 12px;
		font-weight: 500;
		cursor: pointer;
		font: inherit;
		font-size: 12px;
		white-space: nowrap;
	}
	.btn:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}
	.btn-call {
		background: var(--color-primary);
		color: #fff;
		border-color: var(--color-primary);
	}
	.btn-call:not(:disabled):hover {
		background: var(--color-primary-hover);
		border-color: var(--color-primary-hover);
	}
	.btn-cancel {
		background: transparent;
		color: var(--color-text-muted);
		border-color: var(--color-border);
	}
	.btn-cancel:not(:disabled):hover {
		color: var(--color-danger);
		border-color: var(--color-danger);
	}

	@media (max-width: 640px) {
		.page {
			padding: 16px;
		}
		.row-summary {
			grid-template-columns: 8px 28px 1fr auto;
		}
		.row-time {
			display: none;
		}
		.exec-row-body {
			grid-template-columns: 8px 28px 1fr;
			row-gap: 10px;
		}
		.exec-status,
		.row-time,
		.exec-actions {
			grid-column: 1 / -1;
		}
	}
</style>
