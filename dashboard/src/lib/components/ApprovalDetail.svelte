<script lang="ts">
	import {
		type ApprovalResponse,
		type ResolveApprovalRequest
	} from '$lib/session';
	import { page } from '$app/stores';
	import IdentityPath from './IdentityPath.svelte';
	import RiskBadge from './approval/RiskBadge.svelte';
	import ServiceTile from './approval/ServiceTile.svelte';
	import RememberControl from './approval/RememberControl.svelte';
	import ExpiryControl from './approval/ExpiryControl.svelte';
	import { relativeTime } from '$lib/utils/time';
	import { createResolution } from '$lib/approvals/resolution.svelte';
	import { pushToast } from '$lib/stores/toasts.svelte';
	import {
		humanize,
		scopeArgSummary,
		renderPayload,
		formatBytes,
		utf8ByteLength,
		splitDisclosed,
		rememberKeys,
		resolutionToast
	} from '$lib/approvals/format';
	import { onMount } from 'svelte';

	let {
		approval,
		onResolved,
		onBack
	}: {
		approval: ApprovalResponse;
		onResolved?: (a: ApprovalResponse) => void;
		onBack?: () => void;
	} = $props();

	// The detail view navigates back to the queue on resolve (allow / deny /
	// bubble), but stays put on call/cancel so the operator sees the execution
	// result — so we don't hand `onResolved` to the controller (which fires on
	// all three); we invoke it only from our own resolve wrapper.
	const ctrl = createResolution(() => approval);
	const current = $derived(ctrl.current);

	let selectedTier = $state(0);
	let useCustomKey = $state(false);
	let customKey = $state('');
	let ttl = $state('forever');
	let formError = $state<string | null>(null);
	const submitting = $derived(ctrl.submitting);
	const error = $derived(formError ?? ctrl.error);

	const isPending = $derived(ctrl.isPending);
	const execution = $derived(ctrl.execution);
	const executionPending = $derived(ctrl.executionPending);
	const executionRunning = $derived(ctrl.executionRunning);
	const executionTerminal = $derived(ctrl.executionTerminal);

	let tick = $state(0);
	onMount(() => {
		const id = setInterval(() => (tick += 1), 30_000);
		return () => clearInterval(id);
	});
	function rel(iso: string): string {
		void tick;
		return relativeTime(iso);
	}

	$effect(() => {
		void current.id;
		selectedTier = 0;
		useCustomKey = false;
		customKey = '';
		ttl = 'forever';
		formError = null;
	});

	const riskMeta = {
		low: { glyph: '○', label: 'Low risk' },
		med: { glyph: '◐', label: 'Medium risk' },
		high: { glyph: '●', label: 'High risk' }
	} as const;

	const viewerIdentityId = $derived(
		($page.data as { user?: { identity_id?: string } })?.user?.identity_id ?? null
	);
	const isCurrentResolver = $derived(
		!!viewerIdentityId && viewerIdentityId === current.current_resolver_identity_id
	);

	const hasBubbled = $derived(
		!!current.current_resolver_identity_id &&
			current.current_resolver_identity_id !== current.requesting_identity_id
	);

	const primaryKey = $derived(current.derived_keys[0] ?? null);
	const serviceLabel = $derived(primaryKey ? humanize(primaryKey.service) : '—');
	const targetArg = $derived(scopeArgSummary(current.derived_keys));

	const disclosedSplit = $derived(splitDisclosed(current.disclosed_fields));
	const primaryDisclosed = $derived(disclosedSplit.primaries);
	const remainingDisclosed = $derived(disclosedSplit.remaining);

	// Parse the SPIFFE-ish identity_path into (kind, name) units to render the
	// user → agent chain. `spiffe://org/user/alice/agent/henry`.
	interface IdUnit {
		kind: string;
		name: string;
	}
	function parseIdentity(path: string | null): IdUnit[] {
		if (!path) return [];
		const parts = path.replace(/^spiffe:\/\//, '').split('/').filter(Boolean);
		// drop the org slug (first segment), then pair kind/name
		const rest = parts.slice(1);
		const units: IdUnit[] = [];
		for (let i = 0; i + 1 < rest.length; i += 2) {
			units.push({ kind: rest[i], name: rest[i + 1] });
		}
		return units;
	}
	const idUnits = $derived(parseIdentity(current.identity_path));
	const userNode = $derived(idUnits.find((u) => u.kind === 'user')?.name ?? null);
	const agentName = $derived(
		idUnits.length ? idUnits[idUnits.length - 1].name : current.requesting_identity_id.slice(0, 8)
	);

	// The key set the chosen tier would grant is rendered by RememberControl,
	// which owns the selection now that the ladder lives in the action bar.
	const canRemember = $derived(useCustomKey ? !!customKey.trim() : current.suggested_tiers.length > 0);

	async function resolve(resolution: 'allow' | 'deny' | 'allow_remember' | 'bubble_up') {
		formError = null;
		ctrl.clearError();
		const before = current;
		const body: ResolveApprovalRequest = { resolution };
		if (resolution === 'allow_remember') {
			const keys = rememberKeys({
				useCustomKey,
				customKey,
				tiers: current.suggested_tiers,
				selectedTier
			});
			if (!Array.isArray(keys)) {
				formError = keys.error;
				return;
			}
			body.remember_keys = keys;
			if (ttl !== 'forever') body.ttl = ttl;
		}
		const updated = await ctrl.resolve(body);
		if (!updated) return;
		pushToast('success', resolutionToast(resolution, before, updated, body.remember_keys));
		onResolved?.(updated);
	}
</script>

<div class="aq-page aq-view-detail">
	<div class="aq-wrap">
		{#if onBack}
			<button class="aq-back" onclick={onBack}>‹ Queue</button>
		{/if}

		<!-- header: service tile + identity chain + action title -->
		<div class="aq-dhead">
			<ServiceTile name={serviceLabel} size={46} />
			<div style="flex:1; min-width:0;">
				<div class="aq-ident">
					{#if userNode}
						<span class="aq-ident-node user"
							><span class="av">{userNode[0].toUpperCase()}</span>{userNode}</span
						>
						<span class="arr">→</span>
					{/if}
					<span class="aq-ident-node agent">{agentName}</span>
					<span class="arr">→</span>
					<span class="aq-ident-node service">{serviceLabel}</span>
				</div>
				<h2 class="aq-dtitle">
					{current.action_summary}
					<RiskBadge risk={current.risk} />
				</h2>
				<div class="aq-dsub">
					<span class="mono">{targetArg}</span><span>·</span>
					<span>requested {rel(current.created_at)}</span>
					{#if isPending}<span>·</span><span>expires {rel(current.expires_at)}</span>{/if}
				</div>
			</div>
		</div>

		{#if isPending}
			<!-- prominent action bar: scope + expiry + the three resolutions,
			     merged into one control strip above the fold -->
			<div class="aq-actionbar">
				<RememberControl
					tiers={current.suggested_tiers}
					risk={current.risk}
					bind:selectedTier
					bind:useCustomKey
					bind:customKey
				/>
				<ExpiryControl bind:value={ttl} />
				<div class="aq-ab-btns">
					<button class="ovs-btn ovs-btn-danger" disabled={submitting} onclick={() => resolve('deny')}
						>Deny</button
					>
					<button
						class="ovs-btn ovs-btn-secondary"
						disabled={submitting}
						onclick={() => resolve('allow')}>Allow once</button
					>
					<button
						class="ovs-btn ovs-btn-primary aq-ab-primary"
						disabled={submitting || !canRemember}
						onclick={() => resolve('allow_remember')}>Allow &amp; Remember</button
					>
				</div>
			</div>
			{#if error}<div class="aq-error">{error}</div>{/if}
		{:else if executionPending}
			<div class="aq-statusbar banner-pending">
				<div class="aq-statusbar-text">
					<strong>Execution pending.</strong> The approval has been allowed. Trigger the action now,
					or cancel to invalidate. Expires {execution ? rel(execution.expires_at) : ''}.
				</div>
				<div class="aq-ab-btns">
					<button class="ovs-btn ovs-btn-secondary" disabled={submitting} onclick={ctrl.cancelExecution}
						>Cancel</button
					>
					<button class="ovs-btn ovs-btn-primary" disabled={submitting} onclick={ctrl.triggerCall}
						>Call now</button
					>
				</div>
			</div>
			{#if error}<div class="aq-error">{error}</div>{/if}
		{:else if executionRunning}
			<div class="aq-statusbar banner-running" role="status" aria-live="polite">
				Calling upstream action…
			</div>
		{:else if executionTerminal && execution}
			<div class="aq-statusbar banner-{execution.status}" role="status" aria-live="polite">
				{#if execution.status === 'executed'}
					Called successfully.
				{:else if execution.status === 'failed'}
					Call failed{execution.error ? `: ${execution.error}` : ''}.
				{:else if execution.status === 'cancelled'}
					Call was cancelled.
				{:else if execution.status === 'expired'}
					Pending call expired before it ran.
				{/if}
			</div>
			{#if execution.status === 'executed' && (current.cascaded_approval_ids?.length ?? 0) > 0}
				{@const n = current.cascaded_approval_ids!.length}
				<div class="aq-statusbar banner-cascade">
					Also resolved {n} related {n === 1 ? 'approval' : 'approvals'} that the new permission now covers.
				</div>
			{/if}
		{:else}
			<div class="aq-statusbar banner-{current.status}">
				This approval is <strong>{current.status}</strong>.
			</div>
		{/if}

		<div class="aq-detail-grid">
			<!-- LEFT: content hero -->
			<div>
				<div class="aq-hero">
					<div class="aq-hero-bar">
						<div class="who">
							<span class="av">{serviceLabel[0]?.toUpperCase() ?? '?'}</span>
							<div style="min-width:0;">
								<div class="name">{serviceLabel}</div>
								<div class="handle">{targetArg}</div>
							</div>
						</div>
						{#if primaryKey}<span class="tag">{primaryKey.action}</span>{/if}
					</div>
					<div class="aq-hero-body">
						{#if primaryDisclosed.length > 0}
							{#each primaryDisclosed as p, i}
								<div class="aq-principal-key">
									<span class="k">{p.label}</span>
									{#if i === 0}<span class="type-chip">read-only</span>{/if}
								</div>
								<div class="aq-posttext ro">{p.value}</div>
							{/each}
							<div class="aq-edit-row">
								<span class="aq-edit-label">
									Read-only · approve replays it as sent
									{#if primaryDisclosed.some((p) => p.truncated)}<span class="muted small"
											>(truncated)</span
										>{/if}
								</span>
							</div>
						{:else if remainingDisclosed.length === 0}
							<div class="aq-principal-empty">
								No disclosed content for this request. See the raw payload below.
							</div>
						{/if}

						{#if primaryDisclosed.length === 0 && remainingDisclosed.length > 0}
							<div class="aq-edit-row">
								<span class="aq-edit-label">Read-only · approve replays it as sent</span>
							</div>
						{/if}

						{#if remainingDisclosed.length > 0}
							<div class="aq-params">
								<div class="aq-params-cap">
									{remainingDisclosed.length}
									{primaryDisclosed.length > 0 ? 'more ' : ''}parameter{remainingDisclosed.length > 1
										? 's'
										: ''}
								</div>
								{#each remainingDisclosed as f}
									<div class="aq-prow">
										<div class="aq-prow-head">
											<span class="k">{f.label}</span>
										</div>
										{#if f.error}
											<div class="v disclose-error">extract failed: {f.error}</div>
										{:else if f.value !== null && f.value !== undefined}
											<div class="v">
												{f.value}{#if f.truncated}<span class="muted small"> (truncated)</span>{/if}
											</div>
										{:else}
											<div class="v muted">—</div>
										{/if}
									</div>
								{/each}
							</div>
						{/if}

						{#if current.action_detail}
							<details class="aq-raw">
								<summary>Show raw payload</summary>
								<pre class="aq-code">{@html renderPayload(current.action_detail)}</pre>
								{#if current.action_detail_truncated}
									<p class="truncated-note">
										Showing first {formatBytes(utf8ByteLength(current.action_detail))} of {formatBytes(
											current.action_detail_size_bytes
										)} — truncated.
									</p>
								{/if}
							</details>
						{/if}
					</div>
				</div>
			</div>

			<!-- RIGHT: risk + request details (scope and expiry live in the action bar) -->
			<div class="aq-side">
				<div class="aq-riskbar {current.risk}">
					<span class="glyph">{riskMeta[current.risk].glyph}</span>
					<span>{riskMeta[current.risk].label}</span>
					{#if isPending}<span class="expires">expires {rel(current.expires_at)}</span>{/if}
				</div>

				<div class="aq-panel">
					<h3>Request details</h3>
					<dl class="aq-kv">
						<dt>Agent</dt>
						<dd>
							<code class="mono mono-accent">agent:{agentName}</code>
							{#if current.identity_path}
								<IdentityPath path={current.identity_path} pathIds={current.identity_path_ids} />
							{/if}
						</dd>
						{#if primaryKey}
							<dt>Operation</dt>
							<dd><code class="mono">{primaryKey.action}</code></dd>
						{/if}
						{#if current.permission_keys.length > 0}
							<!-- Every uncovered key, one per line: these are exactly what
							     still needs granting, and an action can derive several
							     (one per recipient on a send). -->
							<dt>{current.permission_keys.length > 1 ? 'Permissions' : 'Permission'}</dt>
							<dd class="aq-keylist">
								{#each current.permission_keys as key}
									<code class="mono">{key}</code>
								{/each}
							</dd>
						{/if}
						<dt>Requested</dt>
						<dd>{rel(current.created_at)}</dd>
						{#if hasBubbled}
							<dt>Resolver</dt>
							<dd><code class="mono muted">{current.current_resolver_identity_id}</code></dd>
						{/if}
					</dl>
				</div>

				{#if isPending && !isCurrentResolver}
					<button
						type="button"
						class="aq-bubble"
						disabled={submitting}
						onclick={() => resolve('bubble_up')}
						title="Hand this approval off to the next ancestor in the chain"
					>
						Bubble up to ancestor →
					</button>
				{/if}
			</div>
		</div>
	</div>
</div>

<style>
	/* ============ page scaffold ============ */
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
	.aq-view-detail {
		animation: aqInRight 0.16s ease both;
	}
	@keyframes aqInRight {
		from {
			transform: translateX(22px);
		}
		to {
			transform: none;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.aq-view-detail {
			animation: none;
		}
	}

	.aq-back {
		display: inline-flex;
		align-items: center;
		gap: 7px;
		background: transparent;
		border: 0;
		padding: 4px 0;
		color: var(--color-text-secondary);
		font: var(--text-label);
		cursor: pointer;
		margin-bottom: 14px;
	}
	.aq-back:hover {
		color: var(--color-text);
	}

	/* detail header */
	.aq-dhead {
		display: flex;
		align-items: flex-start;
		gap: 14px;
		margin-bottom: 18px;
	}
	.aq-dtitle {
		font: var(--text-h2);
		margin: 0;
		color: var(--color-text-heading);
		line-height: 1.25;
		display: flex;
		align-items: center;
		gap: 10px;
		flex-wrap: wrap;
	}

	.aq-ident {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
		margin-bottom: 6px;
		font-size: 13px;
	}
	.aq-ident .arr {
		color: var(--color-text-muted);
	}
	.aq-ident-node {
		display: inline-flex;
		align-items: center;
		gap: 6px;
	}
	.aq-ident-node.user {
		font-weight: 500;
		color: var(--color-text);
	}
	.aq-ident-node.user .av {
		width: 20px;
		height: 20px;
		border-radius: 50%;
		background: var(--color-primary);
		color: #fff;
		font-size: 11px;
		font-weight: 600;
		display: flex;
		align-items: center;
		justify-content: center;
	}
	.aq-ident-node.agent {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-primary);
		background: var(--color-primary-bg);
		padding: 2px 8px;
		border-radius: 6px;
	}
	.aq-ident-node.service {
		color: var(--color-text-secondary);
		font-weight: 500;
	}

	.aq-dsub {
		font-size: 13px;
		color: var(--color-text-muted);
		margin-top: 6px;
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
	}
	.aq-dsub .mono {
		font-family: var(--font-mono);
		color: var(--color-text-secondary);
	}

	/* ============ action bar ============ */
	.aq-actionbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 18px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 12px 12px 12px 18px;
		box-shadow: var(--shadow-sm);
	}
	.aq-ab-btns {
		display: flex;
		align-items: center;
		gap: 8px;
		flex: none;
	}

	/* buttons */
	.ovs-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		padding: 10px 16px;
		font-size: 14px;
		font-weight: 500;
		border-radius: 8px;
		border: 1px solid transparent;
		cursor: pointer;
		font-family: inherit;
		transition:
			background 0.1s,
			border-color 0.1s,
			color 0.1s;
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
		border-color: var(--color-primary-hover);
	}
	.ovs-btn-secondary {
		background: var(--color-surface);
		color: var(--color-text);
		border-color: var(--color-border);
	}
	.ovs-btn-secondary:not(:disabled):hover {
		background: var(--color-sidebar);
	}
	.ovs-btn-danger {
		background: transparent;
		color: var(--color-danger);
		border-color: transparent;
	}
	.ovs-btn-danger:not(:disabled):hover {
		background: var(--badge-bg-danger);
	}
	.aq-ab-primary {
		font-weight: 500;
	}

	/* status bars (non-pending states) */
	.aq-statusbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 18px;
		padding: 12px 16px;
		border-radius: 12px;
		font-size: 13px;
		line-height: 1.45;
		border: 1px solid var(--color-border);
		color: var(--color-text);
		background: var(--color-sidebar);
	}
	.aq-statusbar-text {
		min-width: 0;
	}
	.banner-pending {
		border-color: rgba(235, 176, 31, 0.4);
		background: var(--badge-bg-warning);
	}
	.banner-running,
	.banner-allowed {
		border-color: rgba(33, 184, 107, 0.4);
		background: var(--badge-bg-success);
	}
	.banner-executed {
		border-color: rgba(33, 184, 107, 0.4);
		background: var(--badge-bg-success);
		color: var(--color-success);
		font-weight: 500;
	}
	.banner-failed,
	.banner-denied {
		border-color: rgba(229, 56, 54, 0.4);
		background: var(--badge-bg-danger);
		color: var(--color-danger);
		font-weight: 500;
	}
	.banner-cancelled,
	.banner-expired {
		border-color: var(--color-border);
		background: var(--color-sidebar);
		color: var(--color-text-muted);
	}
	.banner-cascade {
		font-size: 12px;
		color: var(--color-text-muted);
		background: var(--color-bg);
		border-color: var(--color-border-subtle);
		margin-top: -8px;
	}

	.aq-error {
		margin-bottom: 18px;
		padding: 8px 12px;
		border: 1px solid var(--color-danger);
		border-radius: 8px;
		background: var(--badge-bg-danger);
		color: var(--color-danger);
		font-size: 12px;
	}

	/* ============ grid ============ */
	.aq-detail-grid {
		display: grid;
		grid-template-columns: 1fr 360px;
		gap: 22px;
		align-items: start;
	}
	@media (max-width: 920px) {
		.aq-detail-grid {
			grid-template-columns: 1fr;
		}
	}

	/* content hero */
	.aq-hero {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 14px;
		overflow: hidden;
	}
	.aq-hero-bar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 10px;
		padding: 11px 16px;
		border-bottom: 1px solid var(--color-border-subtle);
		background: var(--color-sidebar);
	}
	.aq-hero-bar .who {
		display: flex;
		align-items: center;
		gap: 9px;
		min-width: 0;
	}
	.aq-hero-bar .av {
		width: 30px;
		height: 30px;
		border-radius: 50%;
		background: var(--color-primary);
		color: #fff;
		font-weight: 600;
		font-size: 13px;
		display: flex;
		align-items: center;
		justify-content: center;
		flex: none;
	}
	.aq-hero-bar .name {
		font-size: 13px;
		font-weight: 600;
		color: var(--color-text-heading);
	}
	.aq-hero-bar .handle {
		font-size: 12px;
		color: var(--color-text-muted);
		font-family: var(--font-mono);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.aq-hero-bar .tag {
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.02em;
		color: var(--color-text-muted);
		text-transform: lowercase;
	}
	.aq-hero-body {
		padding: 18px;
	}
	.aq-principal-key {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 10px;
	}
	.aq-principal-key .k {
		font-family: var(--font-mono);
		font-size: 13px;
		font-weight: 600;
		color: var(--color-text-heading);
	}
	.aq-posttext {
		width: 100%;
		color: var(--color-text-heading);
		font-family: var(--font-sans);
		font-size: 19px;
		line-height: 1.5;
	}
	.aq-posttext.ro {
		white-space: pre-wrap;
		word-break: break-word;
	}
	.aq-principal-empty {
		font-size: 13px;
		color: var(--color-text-muted);
		font-style: italic;
	}
	.aq-edit-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 10px;
		margin-top: 14px;
		padding-top: 12px;
		border-top: 1px solid var(--color-border-subtle);
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.aq-edit-label {
		display: inline-flex;
		align-items: center;
		gap: 8px;
	}

	/* param rows */
	.aq-params {
		border: 1px solid var(--color-border);
		border-radius: 10px;
		overflow: hidden;
		margin-top: 14px;
	}
	.aq-params-cap {
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--color-text-muted);
		padding: 8px 14px;
		background: var(--color-sidebar);
		border-bottom: 1px solid var(--color-border-subtle);
	}
	.aq-prow {
		padding: 10px 14px;
		border-bottom: 1px solid var(--color-border-subtle);
		font-size: 13px;
	}
	.aq-prow:last-child {
		border-bottom: 0;
	}
	.aq-prow-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		margin-bottom: 3px;
	}
	.aq-prow .k {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-text-secondary);
	}
	.aq-prow .v {
		color: var(--color-text);
		overflow-wrap: anywhere;
		white-space: pre-wrap;
	}
	.aq-prow .v.disclose-error {
		color: var(--color-danger);
		font-style: italic;
	}
	.type-chip {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 600;
		padding: 1px 6px;
		border-radius: 5px;
		background: var(--badge-bg-neutral);
		color: var(--color-text-secondary);
		text-transform: lowercase;
		white-space: nowrap;
	}

	/* raw code */
	.aq-raw {
		margin-top: 14px;
	}
	.aq-raw summary {
		cursor: pointer;
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.aq-raw summary:hover {
		color: var(--color-text);
	}
	.aq-code {
		margin: 10px 0 0;
		padding: 14px 16px;
		background: var(--neutral-900);
		color: #e8e8ee;
		border-radius: 10px;
		font-family: var(--font-mono);
		font-size: 13px;
		line-height: 1.6;
		white-space: pre-wrap;
		word-break: break-word;
		overflow: auto;
		max-height: 320px;
	}
	:global([data-theme='dark']) .aq-code {
		background: #0d0e10;
	}
	.truncated-note {
		margin: 4px 0 0;
		font-size: 11px;
		color: var(--color-text-muted);
	}
	:global(.aq-code .json-key) {
		color: #c4b5ff;
	}
	:global(.aq-code .json-string) {
		color: #7fd1a0;
	}
	:global(.aq-code .json-number) {
		color: var(--orange-500);
	}
	:global(.aq-code .json-bool) {
		color: #c4b5ff;
	}
	:global(.aq-code .json-null),
	:global(.aq-code .json-bracket) {
		color: #8b8d92;
	}

	/* right column */
	.aq-side {
		display: flex;
		flex-direction: column;
		gap: 16px;
		align-self: start;
	}
	.aq-panel {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 16px;
	}
	.aq-panel h3 {
		margin: 0 0 12px;
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--color-text-muted);
	}

	.aq-riskbar {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 11px 14px;
		border-radius: 10px;
		font-size: 13px;
		font-weight: 500;
	}
	.aq-riskbar.low {
		background: var(--badge-bg-success);
		color: #1a9858;
	}
	.aq-riskbar.med {
		background: var(--badge-bg-warning);
		color: #a16207;
	}
	.aq-riskbar.high {
		background: var(--badge-bg-danger);
		color: #c62a28;
	}
	:global([data-theme='dark']) .aq-riskbar.low {
		color: var(--color-success);
	}
	:global([data-theme='dark']) .aq-riskbar.med {
		color: var(--color-warning);
	}
	:global([data-theme='dark']) .aq-riskbar.high {
		color: var(--color-danger);
	}
	.aq-riskbar .glyph {
		font-size: 15px;
	}
	.aq-riskbar .expires {
		margin-left: auto;
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 500;
		opacity: 0.85;
	}

	.aq-kv {
		display: grid;
		grid-template-columns: 92px 1fr;
		row-gap: 12px;
		font-size: 13px;
		margin: 0;
	}
	.aq-kv dt {
		color: var(--color-text-muted);
	}
	.aq-kv dd {
		margin: 0;
		color: var(--color-text);
		display: flex;
		align-items: center;
		gap: 7px;
		flex-wrap: wrap;
		min-width: 0;
		word-break: break-word;
	}

	/* The full permission-key set stacks instead of truncating — what is being
	   granted is the decision the approver is making. */
	.aq-keylist {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 4px;
		overflow-wrap: anywhere;
	}

	.aq-bubble {
		display: inline-flex;
		align-self: flex-start;
		background: transparent;
		border: 0;
		color: var(--color-text-muted);
		font-size: 12px;
		padding: 4px 0;
		cursor: pointer;
		font: inherit;
	}
	.aq-bubble:hover {
		color: var(--color-text);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.mono-accent {
		color: var(--color-primary);
		background: var(--color-primary-bg);
		padding: 1px 5px;
		border-radius: 3px;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.small {
		font-size: 11px;
	}

	@media (max-width: 768px) {
		.aq-page {
			padding: 16px;
		}
		.aq-actionbar,
		.aq-statusbar {
			flex-direction: column;
			align-items: stretch;
			gap: 10px;
		}
		/* stack the merged bar: scope, then expiry, then the buttons */
		.aq-actionbar :global(.aq-remember) {
			order: 1;
		}
		.aq-actionbar :global(.aq-expctl) {
			order: 2;
		}
		.aq-ab-btns {
			order: 3;
		}
		.aq-ab-btns .ovs-btn {
			flex: 1;
			justify-content: center;
		}
	}
</style>
