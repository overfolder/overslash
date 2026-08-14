<script lang="ts">
	import { goto } from '$app/navigation';
	import { highlightJson } from '$lib/api';
	import { createResolution } from '$lib/approvals/resolution.svelte';
	import {
		extractAgentName,
		humanize,
		resolutionToast,
		scopeArgSummary
	} from '$lib/approvals/format';
	import { pushToast } from '$lib/stores/toasts.svelte';
	import type { ApprovalResponse } from '$lib/session';
	import { relativeTime } from '$lib/utils/time';
	import IdentityPath from '../IdentityPath.svelte';
	import RiskBadge from './RiskBadge.svelte';
	import ServiceTile from './ServiceTile.svelte';
	import { onMount } from 'svelte';

	let {
		approval,
		onResolved,
		onExecutionChanged,
		showIdentityPath = false,
		clickable = true
	}: {
		approval: ApprovalResponse;
		/** Called once the API has confirmed — the parent removes the row. */
		onResolved?: (a: ApprovalResponse) => void;
		/** Called after Call now / Cancel, with the updated approval. */
		onExecutionChanged?: (a: ApprovalResponse) => void;
		/** Render the full identity chain on line 2 instead of the agent name. */
		showIdentityPath?: boolean;
		/** Whether the row body navigates to the full detail page. */
		clickable?: boolean;
	} = $props();

	// The row disappears on resolve, so we don't hand `onResolved` to the
	// controller (which also fires on call/cancel — states the row keeps
	// rendering). Only our own resolve wrapper notifies the parent.
	const ctrl = createResolution(() => approval);
	const current = $derived(ctrl.current);

	const isPending = $derived(ctrl.isPending);
	const execution = $derived(ctrl.execution);
	const executionPending = $derived(ctrl.executionPending);
	/** Queued on the async worker — `pending`, but there is nothing to trigger. */
	const executionQueued = $derived(ctrl.executionQueued);
	/** The gated call asked for `execution: "async"` — true before it is approved. */
	const willRunInBackground = $derived(ctrl.willRunInBackground);

	const submitting = $derived(ctrl.submitting);
	const error = $derived(ctrl.error);

	let tick = $state(0);
	onMount(() => {
		const id = setInterval(() => (tick += 1), 30_000);
		return () => clearInterval(id);
	});
	function rel(iso: string): string {
		void tick;
		return relativeTime(iso);
	}

	const primaryKey = $derived(current.derived_keys[0] ?? null);
	const service = $derived(primaryKey?.service ?? 'unknown');
	const serviceLabel = $derived(humanize(service));
	// Summarises every derived key, not just the first — a send to two
	// recipients names both, so the row can't imply the request is narrower
	// than it is.
	const targetArg = $derived(scopeArgSummary(current.derived_keys));
	const agentName = $derived(
		extractAgentName(current.identity_path, current.requesting_identity_id)
	);
	const hasBubbled = $derived(
		!!current.current_resolver_identity_id &&
			current.current_resolver_identity_id !== current.requesting_identity_id
	);

	// The narrowest suggested tier — what ✓✓ writes without asking. Widening it
	// or attaching an expiry is the detail page's job.
	const narrowestTier = $derived(current.suggested_tiers[0] ?? null);

	const executionState = $derived.by((): 'pending' | 'executed' | 'failed' | 'other' => {
		const s = execution?.status;
		if (s === 'pending') return 'pending';
		if (s === 'executed') return 'executed';
		if (s === 'failed') return 'failed';
		return 'other';
	});

	async function resolve(resolution: 'allow' | 'deny' | 'allow_remember') {
		ctrl.clearError();
		const before = current;
		const keys = resolution === 'allow_remember' ? narrowestTier?.keys : undefined;
		if (resolution === 'allow_remember' && !keys) return;

		const updated = await ctrl.resolve(
			keys ? { resolution, remember_keys: keys } : { resolution }
		);
		if (!updated) {
			pushToast('error', ctrl.error ?? 'Failed to resolve approval.');
			return;
		}
		pushToast('success', resolutionToast(resolution, before, updated, keys));
		onResolved?.(updated);
	}

	async function call() {
		ctrl.clearError();
		const updated = await ctrl.triggerCall();
		if (!updated) {
			pushToast('error', ctrl.error ?? 'Failed to dispatch execution.');
			return;
		}
		pushToast('success', `Called — ${serviceLabel}`);
		onExecutionChanged?.(updated);
	}
	async function cancel() {
		ctrl.clearError();
		const updated = await ctrl.cancelExecution();
		if (!updated) {
			pushToast('error', ctrl.error ?? 'Failed to cancel execution.');
			return;
		}
		pushToast('info', `Call cancelled — ${serviceLabel}`);
		onExecutionChanged?.(updated);
	}

	// Clicks that land on the action cluster resolve the request; only clicks on
	// the row body open the detail. Belt and braces with the cluster's own
	// `stopPropagation`: a stray navigation mid-resolve would lose the
	// operator's place in the queue, so the row checks the target too.
	function open(e: Event) {
		if (!clickable) return;
		if ((e.target as Element | null)?.closest('.aq-actions, .aq-result')) return;
		goto(`/approvals/${current.id}`);
	}
	function onKey(e: KeyboardEvent) {
		if (!clickable) return;
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			open(e);
		}
	}
</script>

{#if clickable}
	<!-- The row is one big button onto the detail page. Naming it explicitly
	     keeps its accessible name from swallowing every label inside it. -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="aq-row"
		role="button"
		tabindex="0"
		aria-label="Open approval: {current.action_summary}"
		onclick={open}
		onkeydown={onKey}
	>
		{@render body()}
	</div>
{:else}
	<div class="aq-row is-static">{@render body()}</div>
{/if}

{#snippet body()}
	<span class="aq-rail {current.risk}"></span>
	<ServiceTile name={serviceLabel} size={38} />

	<div class="aq-content">
		<div class="aq-line1">{current.action_summary}</div>
		<div class="aq-line2">
			{#if showIdentityPath && current.identity_path}
				<IdentityPath path={current.identity_path} pathIds={current.identity_path_ids} />
			{:else}
				<span class="svc">{serviceLabel}</span>
				<span class="dot">·</span>
				<span class="mono">{agentName}</span>
			{/if}
			<span class="dot">·</span>
			<span class="mono">{targetArg}</span>
			{#if hasBubbled}<span class="dot">·</span><span class="bubbled">bubbled</span>{/if}
		</div>
		{#if error}
			<div class="aq-rowerr">{error}</div>
		{/if}
	</div>

	<div class="aq-right">
		{#if isPending}
			<div class="aq-when">
				<span class="req">{rel(current.created_at)}</span>
			</div>
			<!-- Approving this does not produce a result here: it hands the call to
			     the worker. Worth one word to the reviewer *before* they decide. -->
			{#if willRunInBackground}
				<span class="exec-pill exec-pill--neutral" title="Runs in the background once approved"
					>background</span
				>
			{/if}
			<RiskBadge risk={current.risk} />
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="aq-actions" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
				<button
					class="aq-iconbtn approve"
					title="Approve once — no rule is written"
					aria-label="Approve once"
					disabled={submitting}
					onclick={() => resolve('allow')}>✓</button
				>
				<button
					class="aq-iconbtn deny"
					title="Deny"
					aria-label="Deny"
					disabled={submitting}
					onclick={() => resolve('deny')}>✕</button
				>
				<button
					class="aq-iconbtn remember"
					title={narrowestTier
						? `Allow & remember · ${narrowestTier.description}\n${narrowestTier.keys.join('\n')}`
						: 'No permission scope to remember — open the request to type one'}
					aria-label="Allow and remember"
					disabled={submitting || !narrowestTier}
					onclick={() => resolve('allow_remember')}><span class="dbl">✓✓</span></button
				>
			</div>
			{#if clickable}<span class="aq-caret">▸</span>{/if}
		{:else}
			<div class="exec-status">
				{#if executionState === 'pending'}
					<span class="exec-pill exec-pill--pending"
						>{executionQueued ? 'queued' : 'awaiting call'}</span
					>
				{:else if executionState === 'executed'}
					<span class="exec-pill exec-pill--executed">called</span>
					{#if execution?.http_status_code != null}
						<code class="mono small muted">{execution.http_status_code}</code>
					{/if}
					{#if execution?.triggered_by === 'auto'}<span class="exec-trigger">auto</span>{/if}
				{:else if executionState === 'failed'}
					<span class="exec-pill exec-pill--failed">failed</span>
					{#if execution?.http_status_code != null}
						<code class="mono small muted">{execution.http_status_code}</code>
					{/if}
				{:else}
					<span class="exec-pill exec-pill--neutral">{execution?.status ?? current.status}</span>
				{/if}
			</div>
			{#if executionPending}
				<!-- svelte-ignore a11y_no_static_element_interactions -->
				<div class="aq-actions" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
					<!-- A queued row belongs to the worker: offering "Call now" would
					     hand the user a button whose only outcome is a 409. -->
					{#if !executionQueued}
						<button class="ovs-btn ovs-btn-primary sm" disabled={submitting} onclick={call}>
							{submitting ? 'Calling…' : 'Call now'}
						</button>
					{/if}
					<button class="ovs-btn ovs-btn-secondary sm" disabled={submitting} onclick={cancel}>
						Cancel
					</button>
				</div>
			{/if}
		{/if}
	</div>

	{#if !isPending && executionState === 'executed' && execution?.result}
		<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
		<details class="aq-result" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
			<summary>Result</summary>
			<pre class="code">{@html highlightJson(execution.result)}</pre>
		</details>
	{/if}
{/snippet}

<style>
	.aq-row {
		display: grid;
		/* minmax(0, 1fr) — not plain 1fr: the content track's min-content floor
		   would otherwise let the mono agent/target strings shove the summary
		   down to an ellipsis in narrow containers (the agents tree panel). */
		grid-template-columns: 4px 38px minmax(0, 1fr) auto;
		gap: 14px;
		align-items: center;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 12px 14px 12px 0;
		margin-bottom: 7px;
		cursor: pointer;
		transition:
			border-color 0.1s,
			box-shadow 0.1s;
		position: relative;
		overflow: hidden;
		text-align: left;
		/* The row lives at 1080px in the queue and ~600px in the agents tree
		   panel, so it drops its lowest-value furniture on its own width
		   rather than the viewport's. */
		container-type: inline-size;
	}
	.aq-row:hover {
		border-color: var(--color-primary);
		box-shadow: var(--shadow-sm);
	}
	.aq-row.is-static,
	.aq-row.is-static:hover {
		cursor: default;
		border-color: var(--color-border);
		box-shadow: none;
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
		/* nowrap, not line-clamp: summaries end in one long unbreakable URL, and
		   clamping breaks on word boundaries — "POST…" instead of "POST api.exa…" */
		white-space: nowrap;
	}
	.aq-line2 {
		font-size: 12px;
		color: var(--color-text-muted);
		display: flex;
		align-items: center;
		gap: 7px;
		min-width: 0;
	}
	.aq-line2 > :global(*) {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	/* Only the two long mono strings give up space; the short labels stay whole. */
	.aq-line2 .dot,
	.aq-line2 .svc,
	.aq-line2 .bubbled {
		flex: none;
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
		white-space: nowrap;
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

	/* the three resolutions — approve once, deny, allow & remember */
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
	.aq-iconbtn.approve {
		color: var(--color-success);
	}
	.aq-iconbtn.approve:not(:disabled):hover {
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
	.aq-iconbtn.remember {
		color: #fff;
		background: var(--color-primary);
		border-color: var(--color-primary);
	}
	.aq-iconbtn.remember:not(:disabled):hover {
		background: var(--color-primary-hover);
		border-color: var(--color-primary-hover);
	}
	.aq-iconbtn .dbl {
		letter-spacing: -0.32em;
		padding-right: 0.32em;
		font-size: 12px;
	}
	.aq-caret {
		color: var(--color-text-muted);
		font-size: 11px;
		width: 14px;
		text-align: center;
	}

	/* execution states (deferred call / called / failed) */
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
	.exec-pill--neutral {
		background: var(--badge-bg-neutral);
		color: var(--color-text-secondary);
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

	.aq-result {
		grid-column: 3 / -1;
		margin-top: 4px;
		cursor: default;
	}
	.aq-result summary {
		cursor: pointer;
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.aq-result summary:hover {
		color: var(--color-text);
	}
	.aq-result .code {
		margin: 6px 0 0;
		padding: 10px 12px;
		background: var(--color-bg);
		border: 1px solid var(--color-border-subtle);
		border-radius: 8px;
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-text);
		overflow: auto;
		max-height: 320px;
		white-space: pre;
	}
	:global(.aq-result .json-key) {
		color: var(--color-primary);
	}
	:global(.aq-result .json-string) {
		color: var(--color-success);
	}
	:global(.aq-result .json-number) {
		color: var(--orange-500);
	}
	:global(.aq-result .json-bool) {
		color: var(--color-primary);
	}
	:global(.aq-result .json-null),
	:global(.aq-result .json-bracket) {
		color: var(--color-text-muted);
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

	/* Last, so it beats the base `display` declarations above. */
	@container (max-width: 640px) {
		.aq-when,
		.aq-caret {
			display: none;
		}
	}

	@media (max-width: 768px) {
		.aq-row {
			grid-template-columns: 4px 34px 1fr;
			padding-right: 12px;
		}
		.aq-right {
			grid-column: 1 / -1;
			padding: 0 0 0 12px;
			justify-content: flex-end;
			gap: 10px;
		}
		.aq-when,
		.aq-caret {
			display: none;
		}
	}
</style>
