<script lang="ts">
	import ApprovalRow from '$lib/components/approval/ApprovalRow.svelte';
	import { session, type ApprovalResponse } from '$lib/session';
	import { humanize, extractAgentName, scopeArgSummary } from '$lib/approvals/format';
	import { collapse, motionDuration } from '$lib/utils/motion';
	import { flip } from 'svelte/animate';

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

	// filters
	let query = $state('');
	let riskFilter = $state<'all' | 'low' | 'med' | 'high'>('all');
	let serviceFilter = $state('all');

	/**
	 * What belongs in "Pending calls": a deferred execution waiting on a
	 * trigger, or — "called but output unread" — one that auto-call (or any
	 * prior /call) already ran to a terminal state while the agent has yet to
	 * collect the result, so the operator still sees the outcome and its HTTP
	 * code. Applied to the loaded list *and* to every in-place update, so the
	 * section and its header count never drift apart.
	 */
	function isPendingCall(a: ApprovalResponse): boolean {
		const s = a.execution?.status;
		if (s === 'pending') return true;
		return (s === 'executed' || s === 'failed') && a.execution?.output_read === false;
	}

	$effect(() => {
		approvals = data.approvals;
	});
	$effect(() => {
		pendingExecutions = data.pendingExecutions.filter(isPendingCall);
	});

	// Row exit: fast enough that the next card lands under a stationary cursor.
	const exitMs = 130;

	function primaryService(a: ApprovalResponse): string {
		return a.derived_keys[0]?.service ?? 'unknown';
	}
	// Summarises every derived key, not just the first — a send to two
	// recipients names both (or "+N more"), so the row can't imply the request
	// is narrower than it is.
	function primaryArg(a: ApprovalResponse): string {
		return scopeArgSummary(a.derived_keys);
	}
	function agentName(a: ApprovalResponse): string {
		return extractAgentName(a.identity_path, a.requesting_identity_id);
	}

	const services = $derived([...new Set(approvals.map(primaryService))].sort());

	// Keep the service filter valid: if the selected service drains out of the
	// queue (all its approvals resolved), its chip disappears — reset to "all"
	// so the filter can't get stuck hiding every row with no way to clear it.
	$effect(() => {
		if (serviceFilter !== 'all' && !services.includes(serviceFilter)) {
			serviceFilter = 'all';
		}
	});

	const visible = $derived.by(() => {
		const q = query.trim().toLowerCase();
		return approvals.filter((a) => {
			if (riskFilter !== 'all' && a.risk !== riskFilter) return false;
			if (serviceFilter !== 'all' && primaryService(a) !== serviceFilter) return false;
			if (q) {
				const hay =
					`${a.action_summary} ${agentName(a)} ${primaryArg(a)} ${primaryService(a)}`.toLowerCase();
				if (!hay.includes(q)) return false;
			}
			return true;
		});
	});

	function dropResolved(updated: ApprovalResponse) {
		const cascaded = new Set(updated.cascaded_approval_ids ?? []);
		approvals = approvals.filter((a) => a.id !== updated.id && !cascaded.has(a.id));
	}

	// A row that resolves into a deferred execution moves from the queue into
	// the "Pending calls" section without a reload.
	async function onRowResolved(updated: ApprovalResponse) {
		dropResolved(updated);
		if (updated.execution?.status === 'pending') {
			try {
				const fresh = await session.get<ApprovalResponse[]>(
					'/v1/approvals?scope=mine&status=allowed'
				);
				pendingExecutions = fresh.filter(isPendingCall);
			} catch {
				// Non-fatal — the section refreshes on the next navigation.
			}
		}
	}

	// Call now / Cancel leave the execution in a new state: keep the row only
	// while it still belongs in the section, so the header count stays honest.
	function onExecutionChanged(updated: ApprovalResponse) {
		pendingExecutions = pendingExecutions
			.map((a) => (a.id === updated.id ? updated : a))
			.filter(isPendingCall);
	}
</script>

<svelte:head><title>Approvals — Overslash</title></svelte:head>

<div class="aq-page">
	<div class="aq-wrap">
		<div class="aq-head">
			<div>
				<h1>Approvals</h1>
				<div class="sub">
					{#if approvals.length > 0}
						<strong>{approvals.length}</strong> in the queue ·
					{:else}
						Queue is clear ·
					{/if}
					<span class="aq-live"><span class="pulse"></span>live</span>
				</div>
			</div>
		</div>

		{#if data.error}
			<div class="banner-error">{data.error}</div>
		{/if}

		{#if approvals.length > 0}
			<div class="aq-filters">
				<label class="aq-search">
					<span class="ico"></span>
					<input placeholder="Search content, agent, or target…" bind:value={query} />
				</label>
				<select class="aq-risk-sel" bind:value={riskFilter}>
					<option value="all">All risk</option>
					<option value="high">High risk</option>
					<option value="med">Medium risk</option>
					<option value="low">Low risk</option>
				</select>
			</div>
			{#if services.length > 1}
				<div class="aq-chiprow">
					<button
						class="aq-chip"
						class:is-active={serviceFilter === 'all'}
						onclick={() => (serviceFilter = 'all')}>All services</button
					>
					{#each services as s}
						<button
							class="aq-chip"
							class:is-active={serviceFilter === s}
							onclick={() => (serviceFilter = s)}
						>
							<span class="mono-tile">{s.slice(0, 2).toUpperCase()}</span>
							{humanize(s)}
						</button>
					{/each}
				</div>
			{/if}
		{/if}

		{#if approvals.length === 0}
			<div class="aq-empty">No approvals waiting for you.</div>
		{:else if visible.length === 0}
			<div class="aq-empty">No requests match your filters.</div>
		{:else}
			<div class="aq-list">
				{#each visible as a (a.id)}
					<div
						class="aq-slot"
						animate:flip={{ duration: motionDuration(exitMs) }}
						out:collapse={{ duration: exitMs }}
					>
						<ApprovalRow approval={a} onResolved={onRowResolved} />
					</div>
				{/each}
			</div>

			<div class="aq-hint">
				<span style="color: var(--color-success)">✓</span> approve once ·
				<span style="color: var(--color-danger)">✕</span> deny ·
				<span style="color: var(--color-primary)">✓✓</span> allow &amp; remember at the narrowest scope
				· open a request to widen scope or set expiry.
			</div>
		{/if}

		{#if pendingExecutions.length > 0}
			<section class="exec-section">
				<header class="exec-head">
					<h2>Pending calls</h2>
					<span class="count">{pendingExecutions.length} pending</span>
				</header>
				<div class="aq-list">
					{#each pendingExecutions as a (a.id)}
						<div
							class="aq-slot"
							animate:flip={{ duration: motionDuration(exitMs) }}
							out:collapse={{ duration: exitMs }}
						>
							<ApprovalRow
								approval={a}
								showIdentityPath
								clickable={false}
								{onExecutionChanged}
							/>
						</div>
					{/each}
				</div>
			</section>
		{/if}
	</div>
</div>

<style>
	.aq-page {
		flex: 1;
		padding: 24px 32px 40px;
		overflow: auto;
		width: 100%;
	}
	.aq-wrap {
		max-width: 1080px;
		margin: 0 auto;
	}

	.aq-head {
		display: flex;
		align-items: flex-end;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 16px;
	}
	.aq-head h1 {
		font: var(--text-h1);
		margin: 0;
		color: var(--color-text-heading);
	}
	.aq-head .sub {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		margin-top: 4px;
	}
	.aq-head .sub strong {
		color: var(--color-text);
	}
	.aq-live {
		display: inline-flex;
		align-items: center;
		gap: 6px;
	}
	.aq-live .pulse {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: var(--color-success);
		box-shadow: 0 0 0 0 rgba(33, 184, 107, 0.5);
		animation: aqPulse 2s infinite;
	}
	@keyframes aqPulse {
		0% {
			box-shadow: 0 0 0 0 rgba(33, 184, 107, 0.45);
		}
		70% {
			box-shadow: 0 0 0 6px rgba(33, 184, 107, 0);
		}
		100% {
			box-shadow: 0 0 0 0 rgba(33, 184, 107, 0);
		}
	}

	.banner-error {
		padding: 10px 14px;
		border: 1px solid var(--color-danger);
		background: var(--badge-bg-danger);
		color: var(--color-danger);
		border-radius: 8px;
		font-size: 13px;
		margin-bottom: 12px;
	}

	/* filter bar */
	.aq-filters {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 14px;
		flex-wrap: wrap;
	}
	.aq-search {
		display: flex;
		align-items: center;
		gap: 8px;
		flex: 1;
		min-width: 220px;
		height: 36px;
		padding: 0 12px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
	}
	.aq-search:focus-within {
		border-color: var(--color-primary);
		outline: 2px solid var(--color-primary-bg);
		outline-offset: -1px;
	}
	.aq-search input {
		flex: 1;
		border: 0;
		background: transparent;
		outline: 0;
		font-size: 13px;
		color: var(--color-text);
	}
	.aq-search input::placeholder {
		color: var(--color-text-muted);
	}
	.aq-search .ico {
		width: 14px;
		height: 14px;
		border-radius: 50%;
		border: 1.5px solid var(--color-text-muted);
		position: relative;
		flex: none;
	}
	.aq-search .ico::after {
		content: '';
		position: absolute;
		right: -3px;
		bottom: -3px;
		width: 6px;
		height: 1.5px;
		background: var(--color-text-muted);
		transform: rotate(45deg);
	}
	.aq-risk-sel {
		height: 36px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		color: var(--color-text);
		font: var(--text-label);
		font-size: 12px;
		padding: 0 8px;
		cursor: pointer;
	}

	.aq-chiprow {
		display: flex;
		align-items: center;
		gap: 6px;
		flex-wrap: wrap;
		margin-bottom: 14px;
	}
	.aq-chip {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		height: 30px;
		padding: 0 11px;
		border-radius: 8px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		color: var(--color-text-secondary);
		font: var(--text-label);
		font-size: 12px;
		cursor: pointer;
		transition: all 0.1s;
		white-space: nowrap;
	}
	.aq-chip:hover {
		background: var(--color-sidebar);
		color: var(--color-text);
	}
	.aq-chip.is-active {
		background: var(--color-primary-bg);
		border-color: transparent;
		color: var(--color-primary);
		font-weight: 500;
	}
	.aq-chip .mono-tile {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 600;
		opacity: 0.8;
	}

	/* rows — the row itself carries its own bottom margin so a collapsing row
	   takes its spacing with it (a flex `gap` cannot be animated away). */
	.aq-list {
		display: flex;
		flex-direction: column;
	}
	.aq-slot {
		min-width: 0;
	}

	.aq-empty {
		border: 1px dashed var(--color-border);
		border-radius: 12px;
		padding: 48px 24px;
		text-align: center;
		color: var(--color-text-muted);
		font-size: 14px;
	}
	.aq-hint {
		margin-top: 16px;
		padding: 11px 14px;
		font-size: 12px;
		color: var(--color-text-muted);
		text-align: center;
		border: 1px dashed var(--color-border);
		border-radius: 10px;
	}

	/* pending calls */
	.exec-section {
		margin-top: 28px;
	}
	.exec-head {
		display: flex;
		align-items: baseline;
		gap: 12px;
		margin-bottom: 10px;
	}
	.exec-head h2 {
		margin: 0;
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.exec-head .count {
		font-size: 12px;
		color: var(--color-text-muted);
	}

	@media (max-width: 768px) {
		.aq-page {
			padding: 16px;
		}
		.aq-head h1 {
			font-size: 24px;
		}
	}
</style>
