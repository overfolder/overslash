<script lang="ts">
	import {
		type ApprovalResponse,
		type ResolveApprovalRequest
	} from '$lib/session';
	import { page } from '$app/stores';
	import IdentityPath from './IdentityPath.svelte';
	import RiskBar from './approval/RiskBar.svelte';
	import RiskBadge from './approval/RiskBadge.svelte';
	import { relativeTime } from '$lib/utils/time';
	import { highlightJson } from '$lib/api';
	import { createResolution } from '$lib/approvals/resolution.svelte';
	import {
		TTL_OPTIONS,
		humanize,
		splitKeys,
		extractAgentName,
		renderPayload,
		formatBytes,
		utf8ByteLength,
		splitDisclosed,
		rememberKeys
	} from '$lib/approvals/format';
	import { onMount } from 'svelte';

	let { approval, onResolved, compact = false }: {
		approval: ApprovalResponse;
		onResolved?: (a: ApprovalResponse) => void;
		compact?: boolean;
	} = $props();

	const ctrl = createResolution(
		() => approval,
		(a) => onResolved?.(a)
	);
	const current = $derived(ctrl.current);

	let selectedTier = $state(0);
	let useCustomKey = $state(false);
	let customKey = $state('');
	let ttl = $state('forever');
	let remember = $state(true);
	let detailsOpen = $state(false);
	let scopeOpen = $state(false);
	// Local validation error (e.g. empty custom key) shown alongside the
	// controller's request error.
	let formError = $state<string | null>(null);
	const submitting = $derived(ctrl.submitting);
	const error = $derived(formError ?? ctrl.error);

	// Refresh the relative-time labels (risk bar's "expires in …", execution
	// expiry hint, etc.) every 30s. Without this the modal can sit open for
	// minutes showing a stale "expires in 30m" while the real countdown ticks
	// down silently. The page-level approvals queue has its own ticker; this
	// one keeps the resolver self-sufficient when it's mounted in a modal or
	// outside that page.
	let tick = $state(0);
	onMount(() => {
		const id = setInterval(() => (tick += 1), 30_000);
		return () => clearInterval(id);
	});
	function rel(iso: string): string {
		void tick;
		return relativeTime(iso);
	}

	// Reset transient form state when the underlying approval id changes.
	$effect(() => {
		void current.id;
		selectedTier = 0;
		useCustomKey = false;
		customKey = '';
		ttl = 'forever';
		remember = true;
		detailsOpen = false;
		scopeOpen = false;
		formError = null;
	});

	const hasBubbled = $derived(
		!!current.current_resolver_identity_id &&
			current.current_resolver_identity_id !== current.requesting_identity_id
	);

	const viewerIdentityId = $derived(
		($page.data as { user?: { identity_id?: string } })?.user?.identity_id ?? null
	);
	const isCurrentResolver = $derived(
		!!viewerIdentityId && viewerIdentityId === current.current_resolver_identity_id
	);
	const orgName = $derived(
		($page.data as { user?: { org_name?: string | null } })?.user?.org_name ?? ''
	);

	const isPending = $derived(ctrl.isPending);
	const execution = $derived(ctrl.execution);
	const executionPending = $derived(ctrl.executionPending);
	const executionRunning = $derived(ctrl.executionRunning);
	const executionTerminal = $derived(ctrl.executionTerminal);

	const primaryKey = $derived(current.derived_keys[0] ?? null);
	const serviceLabel = $derived(primaryKey ? humanize(primaryKey.service) : '—');

	const disclosedSplit = $derived(splitDisclosed(current.disclosed_fields));
	const primaryDisclosed = $derived(disclosedSplit.primaries);
	const remainingDisclosed = $derived(disclosedSplit.remaining);

	const agentName = $derived(extractAgentName(current.identity_path, current.requesting_identity_id));

	const triggerCall = ctrl.triggerCall;
	const cancelExecution = ctrl.cancelExecution;

	function resolve(resolution: 'allow' | 'deny' | 'allow_remember' | 'bubble_up') {
		formError = null;
		ctrl.clearError();
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
		ctrl.resolve(body);
	}

	function onPrimaryAllow() {
		resolve(remember ? 'allow_remember' : 'allow');
	}
</script>

<article class="card" class:compact>
	{#if isPending}
		<RiskBar risk={current.risk} expiresLabel={rel(current.expires_at)} />
	{/if}

	<div class="body">
		{#if !compact}
			<div class="brand-row">
				<span class="brand-eyebrow">Approval</span>
				<span class="service-label">{serviceLabel}</span>
			</div>
		{/if}

		{#if isPending}
			<div class="headline">
				<div class="eyebrow">Approval requested</div>
				<h2 class="title">
					Allow <code class="mono mono-accent">{agentName}</code> to {current.action_summary}?
				</h2>
				{#each primaryDisclosed as p}
					{#if p.value !== null}
						<div class="subtext">
							<span class="muted">{p.label}: </span>
							<em>"{p.value}"</em>
							{#if p.truncated}
								<span class="muted small"> (truncated)</span>
							{/if}
						</div>
					{/if}
				{/each}
			</div>

			<div class="actions">
				<button
					class="btn btn-primary"
					disabled={submitting || (remember && useCustomKey && !customKey.trim())}
					onclick={onPrimaryAllow}
				>
					{remember ? 'Allow & remember' : 'Allow once'}
				</button>

				<div class="scope-row" class:dim={!remember}>
					<label class="check">
						<input type="checkbox" bind:checked={remember} />
					</label>
					<button
						type="button"
						class="scope-trigger"
						disabled={!remember}
						onclick={() => remember && (scopeOpen = !scopeOpen)}
					>
						<div class="scope-text">
							{#if remember}
								{#if useCustomKey}
									<span>Remember <strong>custom scope</strong></span>
									<code class="mono small muted line-2">{customKey || 'service:action:arg'}</code>
								{:else if current.suggested_tiers[selectedTier]}
									{@const tier = current.suggested_tiers[selectedTier]}
									<span>Remember for <strong>{tier.description.toLowerCase()}</strong></span>
									{@const split = splitKeys(tier.keys)}
									<span class="keylist mono small muted">
										{#each split.shown as key}<code>{key}</code>{/each}
										{#if split.hidden > 0}<span>and {split.hidden} more</span>{/if}
									</span>
								{:else}
									<span>Remember for this scope</span>
								{/if}
							{:else}
								<span class="muted">Don't remember — ask again next time</span>
							{/if}
						</div>
						{#if remember}
							<span class="caret" class:open={scopeOpen}>▾</span>
						{/if}
					</button>
					{#if scopeOpen && remember}
						<div class="scope-menu">
							{#each current.suggested_tiers as tier, i}
								{@const split = splitKeys(tier.keys)}
								<button
									type="button"
									class="scope-option"
									class:selected={!useCustomKey && selectedTier === i}
									onclick={() => {
										selectedTier = i;
										useCustomKey = false;
										scopeOpen = false;
									}}
								>
									<div class="scope-option-head">
										<span class="scope-option-label">{tier.description}</span>
										<RiskBadge risk={current.risk} />
									</div>
									<span class="keylist mono small muted">
										{#each split.shown as key}<code>{key}</code>{/each}
										{#if split.hidden > 0}<span>and {split.hidden} more</span>{/if}
									</span>
								</button>
							{/each}
							<button
								type="button"
								class="scope-option"
								class:selected={useCustomKey}
								onclick={() => {
									useCustomKey = true;
									scopeOpen = false;
								}}
							>
								<div class="scope-option-head">
									<span class="scope-option-label">Custom… (advanced)</span>
								</div>
								<span class="muted small">Type a permission key by hand</span>
							</button>
						</div>
					{/if}
				</div>

				{#if useCustomKey && remember}
					<input
						class="custom-key"
						type="text"
						placeholder="service:action:arg"
						bind:value={customKey}
					/>
				{/if}

				<div class="ttl-row" class:dim={!remember}>
					<label for="ttl">Expiry</label>
					<select id="ttl" bind:value={ttl} disabled={!remember}>
						{#each TTL_OPTIONS as opt}
							<option value={opt.value}>{opt.label}</option>
						{/each}
					</select>
				</div>

				{#if error}
					<div class="error">{error}</div>
				{/if}

				<button
					class="btn btn-deny"
					disabled={submitting}
					onclick={() => resolve('deny')}
				>
					Deny
				</button>
			</div>
		{:else if executionPending}
			<div class="banner banner-pending">
				<strong>Execution pending.</strong>
				The approval has been allowed. Trigger the action now, or cancel to
				invalidate — cancelling <em>Allow once</em> means the agent must request
				a fresh approval. Expires {execution ? rel(execution.expires_at) : ''}.
			</div>
			{#if error}<div class="error">{error}</div>{/if}
			<div class="exec-actions">
				<button class="btn btn-primary" disabled={submitting} onclick={triggerCall}>
					Call now
				</button>
				<button class="btn btn-ghost btn-deny" disabled={submitting} onclick={cancelExecution}>
					Cancel
				</button>
			</div>
		{:else if executionRunning}
			<div role="status" aria-live="polite">
				<div class="banner banner-running">Calling upstream action…</div>
			</div>
		{:else if executionTerminal && execution}
			<div role="status" aria-live="polite">
				<div class="banner banner-{execution.status}">
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
					<div class="banner banner-cascade">
						Also resolved {n} related {n === 1 ? 'approval' : 'approvals'} that the new
						permission now covers.
					</div>
				{/if}
			</div>
			{#if execution.status === 'executed' && execution.result}
				<details class="raw">
					<summary>Result</summary>
					<pre class="code">{@html highlightJson(execution.result)}</pre>
				</details>
			{/if}
		{:else}
			<div class="banner banner-{current.status}">
				This approval is <strong>{current.status}</strong>.
			</div>
		{/if}

		<div class="details-block">
			<button
				type="button"
				class="details-toggle"
				onclick={() => (detailsOpen = !detailsOpen)}
			>
				<span class="caret" class:open={detailsOpen}>▶</span>
				<span>{detailsOpen ? 'Hide details' : 'Show details'}</span>
			</button>
			{#if detailsOpen}
				<div class="details-body">
					{#if remainingDisclosed.length > 0 || current.action_detail}
						<div class="details-section">
							<div class="section-eyebrow">Full request</div>
							{#if remainingDisclosed.length > 0}
								<dl class="kv">
									{#each remainingDisclosed as f}
										<dt>{f.label}</dt>
										{#if f.error}
											<dd class="disclose-error">extract failed: {f.error}</dd>
										{:else if f.value !== null && f.value !== undefined}
											<dd>
												<span class="disclose-value">{f.value}</span>
												{#if f.truncated}
													<span class="muted small"> (truncated)</span>
												{/if}
											</dd>
										{:else}
											<dd class="muted">—</dd>
										{/if}
									{/each}
								</dl>
							{/if}
							{#if current.action_detail}
								<details class="raw">
									<summary>Show raw payload</summary>
									<pre class="code">{@html renderPayload(current.action_detail)}</pre>
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
					{/if}

					<dl class="kv">
						<dt>Agent</dt>
						<dd class="agent-row">
							<code class="mono mono-accent">agent:{agentName}</code>
							{#if current.identity_path}
								<span class="muted small">via</span>
								<IdentityPath
									path={current.identity_path}
									pathIds={current.identity_path_ids}
								/>
							{/if}
						</dd>
						{#if current.permission_keys.length > 0}
							<!-- One line per uncovered key: a single action can derive
							     several (one per recipient on a send), and each one is
							     part of what the approver is granting. -->
							<dt>{current.permission_keys.length > 1 ? 'Permissions' : 'Permission'}</dt>
							<dd class="keylist">
								{#each current.permission_keys as key}
									<code class="mono">{key}</code>
								{/each}
							</dd>
						{/if}
						{#if hasBubbled}
							<dt>Resolver</dt>
							<dd>
								<code class="mono muted">{current.current_resolver_identity_id}</code>
							</dd>
						{/if}
					</dl>

					{#if isPending && !isCurrentResolver}
						<button
							type="button"
							class="bubble-up"
							disabled={submitting}
							onclick={() => resolve('bubble_up')}
							title="Hand this approval off to the next ancestor in the chain"
						>
							Bubble up to ancestor →
						</button>
					{/if}
				</div>
			{/if}
		</div>

		{#if !compact && orgName}
			<div class="footer">{orgName}</div>
		{/if}
	</div>
</article>

<style>
	.card {
		display: flex;
		flex-direction: column;
		width: 100%;
		max-width: 480px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		overflow: hidden;
	}
	.card.compact {
		max-width: none;
		border: none;
		border-radius: 0;
		background: transparent;
	}
	.body {
		display: flex;
		flex-direction: column;
		gap: 18px;
		padding: 22px 24px;
	}
	.card.compact .body {
		padding: 8px 0 4px 0;
		gap: 14px;
	}
	.brand-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	.brand-eyebrow,
	.service-label {
		font-size: 11px;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.06em;
		font-weight: 600;
	}

	.headline {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.eyebrow {
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--color-text-muted);
	}
	.title {
		margin: 0;
		font-family: var(--font-sans);
		font-size: 20px;
		font-weight: 600;
		line-height: 1.35;
		color: var(--color-text-heading);
		text-wrap: pretty;
	}
	.subtext {
		font-size: 13px;
		color: var(--color-text-secondary);
		text-wrap: pretty;
	}
	.subtext em {
		color: var(--color-text);
		font-style: normal;
	}

	.actions {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}
	.btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		padding: 12px 18px;
		font-size: 14px;
		font-weight: 500;
		border-radius: 8px;
		border: 1px solid transparent;
		cursor: pointer;
		font-family: inherit;
		transition: background 0.1s, border-color 0.1s, color 0.1s;
	}
	.btn:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		color: #fff;
		border-color: var(--color-primary);
	}
	.btn-primary:not(:disabled):hover {
		background: var(--color-primary-hover);
		border-color: var(--color-primary-hover);
	}
	.btn-deny {
		background: transparent;
		color: var(--color-danger);
		border-color: transparent;
		padding: 10px 18px;
		font-size: 13px;
	}
	.btn-deny:not(:disabled):hover {
		background: var(--badge-bg-danger);
	}
	.btn-ghost {
		background: transparent;
		color: var(--color-text-secondary);
		border-color: var(--color-border);
	}
	.btn-ghost:not(:disabled):hover {
		color: var(--color-text);
	}

	.scope-row {
		position: relative;
		display: flex;
		align-items: stretch;
		background: var(--color-sidebar);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		transition: opacity 0.15s;
	}
	.scope-row.dim {
		opacity: 0.55;
	}
	.check {
		display: flex;
		align-items: center;
		padding: 0 4px 0 12px;
		cursor: pointer;
	}
	.check input {
		accent-color: var(--color-primary);
		cursor: pointer;
	}
	.scope-trigger {
		flex: 1;
		min-width: 0;
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 12px;
		background: transparent;
		border: 0;
		text-align: left;
		font: inherit;
		color: var(--color-text);
		cursor: pointer;
	}
	.scope-trigger:disabled {
		cursor: default;
	}
	.scope-text {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.line-2 {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	/* Keys stack instead of truncating — the omitted ones are exactly what the
	   approver needs to see before granting. */
	.keylist {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 2px;
		min-width: 0;
		overflow-wrap: anywhere;
	}
	.scope-text strong {
		font-weight: 600;
		color: var(--color-text);
	}
	.caret {
		display: inline-block;
		font-size: 10px;
		color: var(--color-text-muted);
		transition: transform 0.15s;
	}
	.caret.open {
		transform: rotate(90deg);
	}
	.scope-trigger .caret.open {
		transform: rotate(180deg);
	}
	.scope-menu {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		box-shadow: var(--shadow-lg);
		padding: 4px;
		z-index: 5;
		display: flex;
		flex-direction: column;
	}
	.scope-option {
		display: flex;
		flex-direction: column;
		gap: 2px;
		padding: 10px 12px;
		background: transparent;
		border: 0;
		border-radius: 6px;
		text-align: left;
		font: inherit;
		color: var(--color-text);
		cursor: pointer;
	}
	.scope-option:hover {
		background: var(--color-sidebar);
	}
	.scope-option.selected {
		background: var(--color-primary-bg);
	}
	.scope-option.selected .scope-option-label {
		color: var(--color-primary);
	}
	.scope-option-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 8px;
	}
	.scope-option-label {
		font-size: 13px;
		font-weight: 500;
	}

	.custom-key {
		padding: 8px 10px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		color: var(--color-text);
		font-family: var(--font-mono);
		font-size: 12px;
		font: var(--text-code);
	}
	.custom-key:focus {
		outline: 2px solid var(--color-primary);
		outline-offset: -1px;
		border-color: var(--color-primary);
	}

	.ttl-row {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 12px;
		color: var(--color-text-muted);
		transition: opacity 0.15s;
	}
	.ttl-row.dim {
		opacity: 0.55;
	}
	.ttl-row select {
		padding: 6px 8px;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 12px;
	}

	.exec-actions {
		display: flex;
		gap: 8px;
	}

	.banner {
		padding: 10px 14px;
		border-radius: 8px;
		font-size: 13px;
		line-height: 1.45;
		border: 1px solid var(--color-border);
		color: var(--color-text);
		background: var(--color-sidebar);
	}
	.banner-pending {
		border-color: rgba(235, 176, 31, 0.4);
		background: var(--badge-bg-warning);
		color: var(--color-text);
	}
	.banner-running,
	.banner-allowed {
		border-color: rgba(33, 184, 107, 0.4);
		background: var(--badge-bg-success);
		color: var(--color-text);
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
		margin-top: 6px;
		border-color: var(--color-border-subtle);
		background: var(--color-bg);
		color: var(--color-text-muted);
		font-size: 12px;
	}

	.error {
		padding: 8px 12px;
		border: 1px solid var(--color-danger);
		border-radius: 6px;
		background: var(--badge-bg-danger);
		color: var(--color-danger);
		font-size: 12px;
	}

	.details-block {
		display: flex;
		flex-direction: column;
		gap: 10px;
		border-top: 1px solid var(--color-border-subtle);
		padding-top: 10px;
	}
	.details-toggle {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		background: transparent;
		border: 0;
		padding: 4px 0;
		color: var(--color-text-muted);
		font-size: 13px;
		cursor: pointer;
		font: inherit;
		align-self: flex-start;
	}
	.details-toggle:hover {
		color: var(--color-text);
	}
	.details-body {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	.details-section {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.section-eyebrow {
		font-size: 11px;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.06em;
		font-weight: 600;
	}

	.kv {
		display: grid;
		grid-template-columns: 100px 1fr;
		row-gap: 8px;
		column-gap: 12px;
		margin: 0;
		font-size: 13px;
	}
	.kv dt {
		color: var(--color-text-muted);
		font-weight: 400;
	}
	.kv dd {
		margin: 0;
		color: var(--color-text);
		min-width: 0;
		word-break: break-word;
	}
	.disclose-value {
		white-space: pre-wrap;
		word-break: break-word;
	}
	.disclose-error {
		color: var(--color-danger);
		font-style: italic;
	}
	.agent-row {
		display: flex;
		align-items: center;
		gap: 6px;
		flex-wrap: wrap;
	}

	.bubble-up {
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
	.bubble-up:hover {
		color: var(--color-text);
	}

	.raw {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.raw summary {
		cursor: pointer;
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.raw summary:hover {
		color: var(--color-text);
	}
	.raw .code {
		margin: 0;
		padding: 10px 12px;
		background: var(--color-bg);
		border: 1px solid var(--color-border-subtle);
		border-radius: 8px;
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-text);
		overflow: auto;
		max-height: 360px;
		white-space: pre;
	}
	.truncated-note {
		margin: 4px 0 0;
		font-size: 11px;
		color: var(--color-text-muted);
	}
	:global(.raw .json-key) {
		color: var(--color-primary);
	}
	:global(.raw .json-string) {
		color: var(--color-success);
	}
	:global(.raw .json-number) {
		color: var(--orange-500);
	}
	:global(.raw .json-bool) {
		color: var(--color-primary);
	}
	:global(.raw .json-null),
	:global(.raw .json-bracket) {
		color: var(--color-text-muted);
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

	.footer {
		font-size: 11px;
		color: var(--color-text-muted);
		text-align: center;
		border-top: 1px solid var(--color-border-subtle);
		padding-top: 12px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
	}
</style>
