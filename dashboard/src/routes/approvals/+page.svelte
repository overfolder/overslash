<script lang="ts">
	import IdentityPath from '$lib/components/IdentityPath.svelte';
	import RiskBadge from '$lib/components/approval/RiskBadge.svelte';
	import ServiceTile from '$lib/components/approval/ServiceTile.svelte';
	import { session, type ApprovalResponse } from '$lib/session';
	import { relativeTime as relativeTimeUtil } from '$lib/utils/time';
	import { humanize, extractAgentName, pickApiError } from '$lib/approvals/format';
	import { goto } from '$app/navigation';
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
	let rowBusy = $state<Record<string, boolean>>({});
	// Per-row so a failure on one row's inline action can't be clobbered by
	// another row's action starting concurrently.
	let rowErrors = $state<Record<string, string | null>>({});
	let execBusy = $state<Record<string, boolean>>({});
	let execError = $state<string | null>(null);

	// filters
	let query = $state('');
	let riskFilter = $state<'all' | 'low' | 'med' | 'high'>('all');
	let serviceFilter = $state('all');

	$effect(() => {
		approvals = data.approvals;
	});
	$effect(() => {
		pendingExecutions = data.pendingExecutions.filter((a) => {
			const s = a.execution?.status;
			if (s === 'pending') return true;
			// "Called but output unread": auto-call (or any prior /call) ran the
			// action to a terminal state, but the agent hasn't read the result
			// yet. Surface so the operator sees the outcome and the HTTP code.
			if ((s === 'executed' || s === 'failed') && a.execution?.output_read === false) {
				return true;
			}
			return false;
		});
	});

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
		return extractAgentName(a.identity_path, a.requesting_identity_id);
	}
	function hasBubbled(a: ApprovalResponse): boolean {
		return (
			!!a.current_resolver_identity_id &&
			a.current_resolver_identity_id !== a.requesting_identity_id
		);
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

	// Inline resolve from the queue. ✓ allows and remembers at the narrowest
	// suggested tier (no expiry — matches the resolver's default); ✕ denies.
	async function resolveRow(a: ApprovalResponse, resolution: 'allow_remember' | 'deny') {
		rowBusy = { ...rowBusy, [a.id]: true };
		rowErrors = { ...rowErrors, [a.id]: null };
		try {
			const body: { resolution: string; remember_keys?: string[] } = { resolution };
			if (resolution === 'allow_remember') {
				const tier = a.suggested_tiers[0];
				if (!tier) {
					// No tier to remember — fall back to a plain allow-once.
					body.resolution = 'allow';
				} else {
					body.remember_keys = tier.keys;
				}
			}
			const updated = await session.post<ApprovalResponse>(`/v1/approvals/${a.id}/resolve`, body);
			dropResolved(updated);
		} catch (e) {
			rowErrors = { ...rowErrors, [a.id]: pickApiError(e, 'Failed to resolve approval.') };
		} finally {
			rowBusy = { ...rowBusy, [a.id]: false };
		}
	}

	function executionStateLabel(a: ApprovalResponse): 'pending' | 'executed' | 'failed' {
		const s = a.execution?.status;
		if (s === 'executed') return 'executed';
		if (s === 'failed') return 'failed';
		return 'pending';
	}
	async function callExecution(a: ApprovalResponse) {
		execBusy = { ...execBusy, [a.id]: true };
		execError = null;
		try {
			await session.post(`/v1/approvals/${a.id}/call`);
			pendingExecutions = pendingExecutions.filter((x) => x.id !== a.id);
		} catch (e) {
			execError = pickApiError(e, 'Failed to dispatch execution.');
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
			execError = pickApiError(e, 'Failed to cancel execution.');
		} finally {
			execBusy = { ...execBusy, [a.id]: false };
		}
	}

	function openDetail(id: string) {
		goto(`/approvals/${id}`);
	}
	function onRowKey(e: KeyboardEvent, id: string) {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			openDetail(id);
		}
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
					<!-- svelte-ignore a11y_no_static_element_interactions -->
					<div
						class="aq-row"
						role="button"
						tabindex="0"
						onclick={() => openDetail(a.id)}
						onkeydown={(e) => onRowKey(e, a.id)}
					>
						<span class="aq-rail {a.risk}"></span>
						<ServiceTile name={primaryService(a)} size={38} />
						<div class="aq-content">
							<div class="aq-line1">{a.action_summary}</div>
							<div class="aq-line2">
								<span>{humanize(primaryService(a))}</span>
								<span class="dot">·</span>
								<span class="mono">{agentName(a)}</span>
								<span class="dot">·</span>
								<span class="mono">{primaryArg(a)}</span>
								{#if hasBubbled(a)}<span class="dot">·</span><span class="bubbled">bubbled</span>{/if}
							</div>
							{#if rowErrors[a.id]}
								<div class="aq-rowerr">{rowErrors[a.id]}</div>
							{/if}
						</div>
						<div class="aq-right">
							<div class="aq-when">
								<span class="req">{relativeTime(a.created_at)}</span>
							</div>
							<RiskBadge risk={a.risk} />
							<!-- svelte-ignore a11y_no_static_element_interactions -->
							<div class="aq-actions" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
								<button
									class="aq-iconbtn allow"
									title="Allow & remember"
									disabled={rowBusy[a.id]}
									onclick={() => resolveRow(a, 'allow_remember')}>✓</button
								>
								<button
									class="aq-iconbtn deny"
									title="Deny"
									disabled={rowBusy[a.id]}
									onclick={() => resolveRow(a, 'deny')}>✕</button
								>
							</div>
							<span class="aq-caret">▸</span>
						</div>
					</div>
				{/each}
			</div>

			<div class="aq-hint">
				Inline <span style="color: var(--color-success)">✓</span> approves at the narrowest scope and
				remembers it · open a request to widen scope or set expiry.
			</div>
		{/if}

		{#if pendingExecutions.length > 0}
			<section class="exec-section">
				<header class="exec-head">
					<h2>Pending calls</h2>
					<span class="count">{pendingExecutions.length} pending</span>
				</header>
				{#if execError}
					<div class="banner-error">{execError}</div>
				{/if}
				<div class="aq-list">
					{#each pendingExecutions as a (a.id)}
						{@const state = executionStateLabel(a)}
						<div class="aq-row exec-row exec-row--{state}">
							<span class="aq-rail {a.risk}"></span>
							<ServiceTile name={primaryService(a)} size={38} />
							<div class="aq-content">
								<div class="aq-line1">{a.action_summary}</div>
								<div class="aq-line2">
									{#if a.identity_path}
										<IdentityPath path={a.identity_path} pathIds={a.identity_path_ids} />
									{:else}
										<span class="mono">{agentName(a)}</span>
									{/if}
								</div>
							</div>
							<div class="aq-right">
								<div class="exec-status">
									{#if state === 'pending'}
										<span class="exec-pill exec-pill--pending">awaiting call</span>
									{:else if state === 'executed'}
										<span class="exec-pill exec-pill--executed">called</span>
										{#if a.execution?.http_status_code != null}
											<code class="mono small muted">{a.execution.http_status_code}</code>
										{/if}
										{#if a.execution?.triggered_by === 'auto'}<span class="exec-trigger">auto</span
											>{/if}
									{:else}
										<span class="exec-pill exec-pill--failed">failed</span>
										{#if a.execution?.http_status_code != null}
											<code class="mono small muted">{a.execution.http_status_code}</code>
										{/if}
									{/if}
								</div>
								{#if state === 'pending'}
									<!-- svelte-ignore a11y_no_static_element_interactions -->
									<div class="aq-actions" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
										<button
											class="ovs-btn ovs-btn-primary sm"
											disabled={execBusy[a.id]}
											onclick={() => callExecution(a)}
										>
											{execBusy[a.id] ? 'Calling…' : 'Call now'}
										</button>
										<button
											class="ovs-btn ovs-btn-secondary sm"
											disabled={execBusy[a.id]}
											onclick={() => cancelExecution(a)}
										>
											Cancel
										</button>
									</div>
								{/if}
							</div>
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

	/* rows */
	.aq-list {
		display: flex;
		flex-direction: column;
		gap: 7px;
	}
	.aq-row {
		display: grid;
		grid-template-columns: 4px 38px 1fr auto;
		gap: 14px;
		align-items: center;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 12px 14px 12px 0;
		cursor: pointer;
		transition:
			border-color 0.1s,
			box-shadow 0.1s;
		position: relative;
		overflow: hidden;
		text-align: left;
	}
	.aq-row:hover {
		border-color: var(--color-primary);
		box-shadow: var(--shadow-sm);
	}
	.aq-rail {
		width: 4px;
		align-self: stretch;
		border-radius: 4px 0 0 4px;
	}
	.aq-rail.low {
		background: var(--color-success);
	}
	.aq-rail.med {
		background: var(--color-warning);
	}
	.aq-rail.high {
		background: var(--color-danger);
	}
	.aq-content {
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 3px;
	}
	.aq-line1 {
		font-size: 14px;
		color: var(--color-text-heading);
		line-height: 1.45;
		overflow: hidden;
		text-overflow: ellipsis;
		display: -webkit-box;
		-webkit-line-clamp: 1;
		line-clamp: 1;
		-webkit-box-orient: vertical;
	}
	.aq-line2 {
		font-size: 12px;
		color: var(--color-text-muted);
		display: flex;
		align-items: center;
		gap: 7px;
		flex-wrap: wrap;
	}
	.aq-line2 .dot {
		color: var(--color-border);
	}
	.aq-line2 .mono {
		font-family: var(--font-mono);
		color: var(--color-text-secondary);
	}
	.aq-line2 .bubbled {
		color: var(--color-warning);
	}
	.aq-rowerr {
		margin-top: 4px;
		font-size: 12px;
		color: var(--color-danger);
	}

	.aq-right {
		display: flex;
		align-items: center;
		gap: 14px;
	}
	.aq-when {
		display: flex;
		flex-direction: column;
		align-items: flex-end;
		gap: 3px;
		min-width: 72px;
	}
	.aq-when .req {
		font-size: 11px;
		color: var(--color-text-muted);
		font-family: var(--font-mono);
	}
	.aq-actions {
		display: flex;
		align-items: center;
		gap: 6px;
	}
	.aq-iconbtn {
		width: 30px;
		height: 30px;
		border-radius: 8px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		font-size: 13px;
		transition: all 0.1s;
	}
	.aq-iconbtn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.aq-iconbtn.allow {
		color: var(--color-success);
	}
	.aq-iconbtn.allow:not(:disabled):hover {
		background: var(--badge-bg-success);
		border-color: transparent;
	}
	.aq-iconbtn.deny {
		color: var(--color-danger);
	}
	.aq-iconbtn.deny:not(:disabled):hover {
		background: var(--badge-bg-danger);
		border-color: transparent;
	}
	.aq-caret {
		color: var(--color-text-muted);
		font-size: 11px;
		width: 14px;
		text-align: center;
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
	.exec-row {
		cursor: default;
	}
	.exec-row:hover {
		border-color: var(--color-border);
		box-shadow: none;
	}
	.exec-status {
		display: flex;
		align-items: center;
		gap: 6px;
		flex-wrap: wrap;
	}
	.exec-pill {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 600;
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

	.ovs-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border-radius: 8px;
		border: 1px solid transparent;
		cursor: pointer;
		font-family: inherit;
		font-weight: 500;
		transition: all 0.1s;
	}
	.ovs-btn.sm {
		padding: 6px 12px;
		font-size: 12px;
	}
	.ovs-btn:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}
	.ovs-btn-primary {
		background: var(--color-primary);
		color: #fff;
		border-color: var(--color-primary);
	}
	.ovs-btn-primary:not(:disabled):hover {
		background: var(--color-primary-hover);
	}
	.ovs-btn-secondary {
		background: var(--color-surface);
		color: var(--color-text-secondary);
		border-color: var(--color-border);
	}
	.ovs-btn-secondary:not(:disabled):hover {
		color: var(--color-danger);
		border-color: var(--color-danger);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.small {
		font-size: 11px;
	}
	.muted {
		color: var(--color-text-muted);
	}

	@media (max-width: 768px) {
		.aq-page {
			padding: 16px;
		}
		.aq-row {
			grid-template-columns: 4px 34px 1fr;
			padding-right: 12px;
		}
		.aq-right {
			display: none;
		}
		.aq-head h1 {
			font-size: 24px;
		}
	}
</style>
