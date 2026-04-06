<script lang="ts">
	import {
		session,
		ApiError,
		type ApprovalResponse,
		type ResolveApprovalRequest
	} from '$lib/session';

	let { approval, onResolved }: {
		approval: ApprovalResponse;
		onResolved?: (a: ApprovalResponse) => void;
	} = $props();

	let override = $state<ApprovalResponse | null>(null);
	const current = $derived(override ?? approval);
	let selectedTier = $state(0);
	let ttl = $state('24h');
	let submitting = $state(false);
	let error = $state<string | null>(null);

	const ttlOptions = [
		{ value: '1h', label: '1 hour' },
		{ value: '24h', label: '24 hours' },
		{ value: '7d', label: '7 days' },
		{ value: '30d', label: '30 days' },
		{ value: 'forever', label: 'Forever' }
	];

	const isPending = $derived(current.status === 'pending');

	async function resolve(resolution: 'allow' | 'deny' | 'allow_remember') {
		submitting = true;
		error = null;
		try {
			const body: ResolveApprovalRequest = { resolution };
			if (resolution === 'allow_remember') {
				const tier = current.suggested_tiers[selectedTier];
				if (!tier) {
					error = 'Select a permission scope to remember.';
					submitting = false;
					return;
				}
				body.remember_keys = tier.keys;
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

<div class="resolver">
	{#if !isPending}
		<div class="banner banner-{current.status}">
			This approval is <strong>{current.status}</strong>.
		</div>
	{/if}

	<section class="block">
		<div class="label">Action</div>
		<div class="summary">{current.action_summary}</div>
	</section>

	<section class="block">
		<div class="label">Requested by identity</div>
		<code class="mono">{current.identity_id}</code>
	</section>

	<section class="block">
		<div class="label">Permission keys</div>
		<ul class="keys">
			{#each current.permission_keys as key}
				<li><code class="mono">{key}</code></li>
			{/each}
		</ul>
	</section>

	<section class="block">
		<div class="label">Expires</div>
		<div>{current.expires_at}</div>
	</section>

	{#if isPending}
		<section class="block">
			<div class="label">Remember scope (for "Allow & remember")</div>
			<div class="tiers">
				{#each current.suggested_tiers as tier, i}
					<label class="tier" class:selected={selectedTier === i}>
						<input
							type="radio"
							name="tier"
							value={i}
							checked={selectedTier === i}
							onchange={() => (selectedTier = i)}
						/>
						<div class="tier-body">
							<div class="tier-desc">{tier.description}</div>
							<div class="tier-keys">
								{#each tier.keys as k}
									<code class="mono">{k}</code>
								{/each}
							</div>
						</div>
					</label>
				{/each}
			</div>

			<div class="ttl-row">
				<label for="ttl">Remember for</label>
				<select id="ttl" bind:value={ttl}>
					{#each ttlOptions as opt}
						<option value={opt.value}>{opt.label}</option>
					{/each}
				</select>
			</div>
		</section>

		{#if error}
			<div class="error">{error}</div>
		{/if}

		<div class="actions">
			<button
				class="btn btn-deny"
				disabled={submitting}
				onclick={() => resolve('deny')}
			>
				Deny
			</button>
			<button
				class="btn btn-allow-once"
				disabled={submitting}
				onclick={() => resolve('allow')}
			>
				Allow once
			</button>
			<button
				class="btn btn-allow-remember"
				disabled={submitting}
				onclick={() => resolve('allow_remember')}
			>
				Allow & remember
			</button>
		</div>
	{/if}
</div>

<style>
	.resolver {
		display: flex;
		flex-direction: column;
		gap: 1.25rem;
	}
	.block {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.label {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
	}
	.summary {
		font-size: 1.05rem;
		color: var(--color-text);
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.85rem;
		background: var(--color-surface);
		padding: 0.1rem 0.4rem;
		border-radius: 4px;
		border: 1px solid var(--color-border);
	}
	.keys {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.tiers {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.tier {
		display: flex;
		gap: 0.6rem;
		padding: 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		cursor: pointer;
		align-items: flex-start;
	}
	.tier.selected {
		border-color: var(--color-primary);
		background: var(--color-surface);
	}
	.tier-body {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.tier-desc {
		font-weight: 500;
		color: var(--color-text);
	}
	.tier-keys {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
	}
	.ttl-row {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		margin-top: 0.75rem;
	}
	.ttl-row select {
		padding: 0.4rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
		color: var(--color-text);
	}
	.actions {
		display: flex;
		gap: 0.6rem;
		justify-content: flex-end;
	}
	.btn {
		padding: 0.6rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		font-size: 0.9rem;
		cursor: pointer;
		background: var(--color-surface);
		color: var(--color-text);
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-deny {
		border-color: #b94a48;
		color: #b94a48;
	}
	.btn-allow-once {
		border-color: var(--color-primary);
		color: var(--color-primary);
	}
	.btn-allow-remember {
		background: var(--color-primary);
		color: white;
		border-color: var(--color-primary);
	}
	.banner {
		padding: 0.75rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
	}
	.banner-allowed {
		border-color: #2e7d32;
		color: #2e7d32;
	}
	.banner-denied {
		border-color: #b94a48;
		color: #b94a48;
	}
	.error {
		padding: 0.6rem 0.8rem;
		border: 1px solid #b94a48;
		border-radius: 6px;
		color: #b94a48;
		background: rgba(185, 74, 72, 0.08);
		font-size: 0.85rem;
	}
</style>
