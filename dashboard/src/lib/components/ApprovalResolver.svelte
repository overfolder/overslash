<script lang="ts">
	import {
		session,
		ApiError,
		type ApprovalResponse,
		type ResolveApprovalRequest
	} from '$lib/session';
	import IdentityPath from './IdentityPath.svelte';
	import { relativeTime } from '$lib/utils/time';

	let { approval, onResolved, compact = false }: {
		approval: ApprovalResponse;
		onResolved?: (a: ApprovalResponse) => void;
		compact?: boolean;
	} = $props();

	let override = $state<ApprovalResponse | null>(null);
	const current = $derived(override ?? approval);
	let selectedTier = $state(0);
	let useCustomKey = $state(false);
	let customKey = $state('');
	let ttl = $state('forever');
	let submitting = $state(false);
	let error = $state<string | null>(null);

	const hasBubbled = $derived(
		!!current.current_resolver_identity_id &&
			current.current_resolver_identity_id !== current.requesting_identity_id
	);

	const ttlOptions = [
		{ value: 'forever', label: 'Never' },
		{ value: '1h', label: '1 hour' },
		{ value: '24h', label: '24 hours' },
		{ value: '7d', label: '7 days' },
		{ value: '30d', label: '30 days' }
	];

	const isPending = $derived(current.status === 'pending');

	// Derive Service / Action display from the first parsed permission key.
	// `derived_keys` comes from the API as `{service, action, arg}`.
	const primary = $derived(current.derived_keys[0] ?? null);
	const serviceLabel = $derived(primary ? humanize(primary.service) : '—');
	const actionLabel = $derived(primary ? primary.action : '—');

	function humanize(slug: string): string {
		// "github" -> "GitHub", "google_calendar" -> "Google Calendar"
		const known: Record<string, string> = {
			github: 'GitHub',
			gitlab: 'GitLab',
			google_calendar: 'Google Calendar',
			gmail: 'Gmail'
		};
		if (known[slug]) return known[slug];
		return slug
			.split(/[_\-]/)
			.map((s) => s.charAt(0).toUpperCase() + s.slice(1))
			.join(' ');
	}

	async function resolve(resolution: 'allow' | 'deny' | 'allow_remember' | 'bubble_up') {
		submitting = true;
		error = null;
		try {
			const body: ResolveApprovalRequest = { resolution };
			if (resolution === 'allow_remember') {
				if (useCustomKey) {
					const k = customKey.trim();
					if (!k) {
						error = 'Enter a permission key to remember.';
						submitting = false;
						return;
					}
					body.remember_keys = [k];
				} else {
					const tier = current.suggested_tiers[selectedTier];
					if (!tier) {
						error = 'Select a permission scope to remember.';
						submitting = false;
						return;
					}
					body.remember_keys = tier.keys;
				}
				if (ttl !== 'forever') body.ttl = ttl;
			}
			const updated = await session.post<ApprovalResponse>(
				`/v1/approvals/${current.id}/resolve`,
				body
			);
			override = updated;
			onResolved?.(updated);
		} catch (e) {
			if (e instanceof ApiError) {
				const body = e.body as { error?: string } | string;
				if (typeof body === 'object' && body && 'error' in body) {
					error = body.error ?? `Error ${e.status}`;
				} else {
					error = typeof body === 'string' ? body : `Error ${e.status}`;
				}
			} else {
				error = 'Network error';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<div class="root" class:card={!compact}>
	{#if !compact}
		<h1>Approval Request</h1>
		<p class="summary">{current.action_summary}</p>
	{/if}

	<dl class="meta">
		<dt>Agent</dt>
		<dd>
			{#if current.identity_path}
				<IdentityPath path={current.identity_path} />
			{:else}
				<code class="mono mute">{current.identity_id}</code>
			{/if}
		</dd>

		{#if hasBubbled}
			<dt>Resolver</dt>
			<dd><code class="mono mute">{current.current_resolver_identity_id}</code></dd>
		{/if}

		<dt>Service</dt>
		<dd>{serviceLabel}</dd>

		<dt>Action</dt>
		<dd><code class="mono">{actionLabel}</code></dd>

		<dt>Requested</dt>
		<dd>{relativeTime(current.created_at)}</dd>

		<dt>Expires</dt>
		<dd>{relativeTime(current.expires_at)}</dd>
	</dl>

	{#if current.derived_keys.length > 0}
		<details class="derived">
			<summary>Derived keys ({current.derived_keys.length})</summary>
			<ul>
				{#each current.derived_keys as dk}
					<li><code class="mono">{dk.service} · {dk.action} · {dk.arg}</code></li>
				{/each}
			</ul>
		</details>
	{/if}

	{#if !isPending}
		<div class="banner banner-{current.status}">
			This approval is <strong>{current.status}</strong>.
		</div>
	{:else}
		<div class="scope-block">
			<div class="scope-label">Scope</div>
			<div class="tiers">
				{#each current.suggested_tiers as tier, i}
					<label class="tier" class:selected={!useCustomKey && selectedTier === i}>
						<input
							type="radio"
							name="tier"
							value={i}
							checked={!useCustomKey && selectedTier === i}
							onchange={() => {
								selectedTier = i;
								useCustomKey = false;
							}}
						/>
						<div class="tier-body">
							<code class="mono tier-key">{tier.keys[0]}{tier.keys.length > 1
									? ` +${tier.keys.length - 1}`
									: ''}</code>
							<div class="tier-desc">{tier.description}</div>
						</div>
					</label>
				{/each}
				<label class="tier" class:selected={useCustomKey}>
					<input
						type="radio"
						name="tier"
						checked={useCustomKey}
						onchange={() => (useCustomKey = true)}
					/>
					<div class="tier-body">
						<div class="tier-desc">Custom… (advanced)</div>
						{#if useCustomKey}
							<input
								class="custom-key"
								type="text"
								placeholder="service:action:arg"
								bind:value={customKey}
							/>
						{/if}
					</div>
				</label>
			</div>

			<div class="expiry-row">
				<label for="ttl">Expiry:</label>
				<select id="ttl" bind:value={ttl}>
					{#each ttlOptions as opt}
						<option value={opt.value}>{opt.label}</option>
					{/each}
				</select>
			</div>
		</div>

		{#if error}
			<div class="error">{error}</div>
		{/if}

		<div class="actions">
			<button
				class="btn btn-allow-once"
				disabled={submitting}
				onclick={() => resolve('allow')}
			>
				Allow once
			</button>
			<button
				class="btn btn-primary"
				disabled={submitting || (useCustomKey && !customKey.trim())}
				onclick={() => resolve('allow_remember')}
			>
				Allow &amp; Remember
			</button>
			<button
				class="btn btn-bubble"
				disabled={submitting}
				title="Hand this approval off to the next ancestor in the chain"
				onclick={() => resolve('bubble_up')}
			>
				Bubble up
			</button>
			<button class="btn btn-deny" disabled={submitting} onclick={() => resolve('deny')}>
				Deny
			</button>
		</div>
	{/if}
</div>

<style>
	.root {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		width: 100%;
	}
	.card {
		max-width: 520px;
		background: #fff;
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 1.75rem 2rem;
		box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
	}
	.derived summary {
		cursor: pointer;
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	.derived ul {
		margin: 0.4rem 0 0 0;
		padding: 0;
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}
	.custom-key {
		margin-top: 0.4rem;
		width: 100%;
		padding: 0.35rem 0.5rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		font-family: var(--font-mono);
		font-size: 0.78rem;
	}
	.btn-allow-once {
		background: #fff;
		color: var(--color-primary);
		border-color: var(--color-primary);
	}
	h1 {
		margin: 0;
		font-size: 1.15rem;
		font-weight: 700;
		color: var(--color-text);
	}
	.summary {
		margin: 0;
		color: var(--color-text);
		font-size: 0.9rem;
	}
	.meta {
		display: grid;
		grid-template-columns: 90px 1fr;
		gap: 0.55rem 1rem;
		margin: 0.25rem 0 0 0;
	}
	.meta dt {
		color: var(--color-text-muted);
		font-size: 0.8rem;
		align-self: center;
	}
	.meta dd {
		margin: 0;
		font-size: 0.85rem;
		color: var(--color-text);
		align-self: center;
		min-width: 0;
		word-break: break-all;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.8rem;
	}
	.mute {
		color: var(--color-text-muted);
	}
	.scope-block {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		margin-top: 0.25rem;
	}
	.scope-label {
		font-weight: 600;
		font-size: 0.85rem;
		color: var(--color-text);
	}
	.tiers {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.tier {
		display: flex;
		align-items: flex-start;
		gap: 0.6rem;
		padding: 0.65rem 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		cursor: pointer;
		background: #fff;
		transition: background 0.1s, border-color 0.1s;
	}
	.tier:hover {
		border-color: #c7c2f0;
	}
	.tier.selected {
		border-color: var(--color-primary);
		background: #efeefb;
	}
	.tier input {
		margin-top: 0.15rem;
		accent-color: var(--color-primary);
	}
	.tier-body {
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
		min-width: 0;
	}
	.tier-key {
		color: var(--color-primary);
		font-size: 0.78rem;
		word-break: break-all;
	}
	.tier-desc {
		color: var(--color-text-muted);
		font-size: 0.75rem;
	}
	.expiry-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-top: 0.4rem;
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	.expiry-row select {
		padding: 0.3rem 0.5rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: #fff;
		color: var(--color-text);
		font-size: 0.8rem;
	}
	.actions {
		display: flex;
		gap: 0.6rem;
		margin-top: 0.5rem;
	}
	.btn {
		padding: 0.55rem 1rem;
		border-radius: 6px;
		font-size: 0.85rem;
		font-weight: 500;
		cursor: pointer;
		border: 1px solid transparent;
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		color: #fff;
		border-color: var(--color-primary);
	}
	.btn-deny {
		background: #fff;
		color: #d14343;
		border-color: #d14343;
	}
	.btn-bubble {
		background: #fff;
		color: var(--color-text);
		border-color: var(--color-border);
	}
	.banner {
		padding: 0.75rem 1rem;
		border-radius: 8px;
		font-size: 0.85rem;
		border: 1px solid var(--color-border);
	}
	.banner-allowed {
		border-color: #2e7d32;
		color: #2e7d32;
		background: rgba(46, 125, 50, 0.06);
	}
	.banner-denied {
		border-color: #d14343;
		color: #d14343;
		background: rgba(209, 67, 67, 0.06);
	}
	.error {
		padding: 0.6rem 0.8rem;
		border: 1px solid #d14343;
		border-radius: 6px;
		color: #d14343;
		background: rgba(209, 67, 67, 0.06);
		font-size: 0.8rem;
	}
</style>
