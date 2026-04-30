<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { session } from '$lib/session';

	type StatusResponse = {
		status: 'pending' | 'fulfilled';
		org_id?: string;
		redirect_to?: string;
	};

	let view: 'loading' | 'ready' | 'timeout' | 'error' = 'loading';
	let orgId: string | null = null;
	let redirectTo: string | null = null;
	let errorMsg: string | null = null;
	let switching = false;
	let switchError: string | null = null;

	onMount(() => {
		const sessionId = $page.url.searchParams.get('session_id');
		if (!sessionId) {
			view = 'error';
			errorMsg = 'No session ID in URL.';
			return;
		}

		let elapsed = 0;
		const MAX_WAIT_MS = 30_000;
		const POLL_MS = 2_000;

		const timer = setInterval(async () => {
			elapsed += POLL_MS;
			try {
				const res = await session.get<StatusResponse>(
					`/v1/billing/checkout/${encodeURIComponent(sessionId)}/status`
				);
				if (res.status === 'fulfilled') {
					clearInterval(timer);
					orgId = res.org_id ?? null;
					redirectTo = res.redirect_to ?? null;
					view = 'ready';
					// Return so a tick at the timeout boundary doesn't overwrite
					// 'ready' with 'timeout' on the same callback run.
					return;
				}
			} catch {
				// Keep polling — transient errors are expected during provisioning.
			}
			if (elapsed >= MAX_WAIT_MS) {
				clearInterval(timer);
				view = 'timeout';
			}
		}, POLL_MS);

		return () => clearInterval(timer);
	});

	async function enterOrg() {
		if (switching) return;
		switching = true;
		switchError = null;
		try {
			// Mint a new session JWT scoped to the new org BEFORE navigating —
			// otherwise the user lands on the new org's subdomain still
			// authenticated as their previous org.
			if (orgId) {
				const res = await session.post<{ redirect_to?: string }>('/auth/switch-org', {
					org_id: orgId
				});
				const target = res?.redirect_to ?? redirectTo;
				if (target) {
					window.location.href = target;
					return;
				}
				window.location.reload();
				return;
			}
			if (redirectTo) {
				window.location.href = redirectTo;
				return;
			}
			window.location.reload();
		} catch (e) {
			switchError = e instanceof Error ? e.message : 'Failed to enter org';
			switching = false;
		}
	}
</script>

<svelte:head>
	<title>Setting up your team — Overslash</title>
</svelte:head>

<div class="page">
	<div class="card">
		{#if view === 'loading'}
			<div class="spinner" aria-label="Setting up your org…"></div>
			<h1>Setting up your team org…</h1>
			<p>Payment confirmed. We're provisioning your workspace — this takes just a moment.</p>

		{:else if view === 'ready'}
			<div class="check">✓</div>
			<h1>Your team org is ready</h1>
			<p>Everything is set up. Click below to enter your new workspace.</p>
			<button class="btn-primary" onclick={enterOrg} disabled={switching}>
				{switching ? 'Entering…' : 'Enter org →'}
			</button>
			{#if switchError}
				<p class="error">{switchError}</p>
			{/if}

		{:else if view === 'timeout'}
			<div class="warn">⚠</div>
			<h1>Still setting up…</h1>
			<p>
				Your payment was received. The org should appear in your org switcher shortly.
				Refresh to check, or contact <a href="mailto:support@overslash.com">support</a> if it
				doesn't show up.
			</p>
			<button class="btn-secondary" onclick={() => window.location.reload()}>
				Refresh
			</button>

		{:else if view === 'error'}
			<div class="warn">⚠</div>
			<h1>Something went wrong</h1>
			<p>{errorMsg ?? 'An unexpected error occurred.'}</p>
			<a href="/billing/new-team" class="btn-secondary">Try again</a>
		{/if}
	</div>
</div>

<style>
	.page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem 1rem;
		background: var(--color-bg);
	}

	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 2.5rem 2rem;
		max-width: 420px;
		width: 100%;
		text-align: center;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.75rem;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
	}

	h1 {
		margin: 0;
		font-size: 1.1rem;
		font-weight: 700;
		color: var(--color-text-heading, var(--color-text));
	}

	p {
		margin: 0;
		font-size: 0.875rem;
		color: var(--color-text-muted);
		max-width: 320px;
	}

	.spinner {
		width: 2.5rem;
		height: 2.5rem;
		border: 3px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.check {
		font-size: 2rem;
		color: var(--color-success, #1b8a3a);
	}

	.warn {
		font-size: 2rem;
		color: var(--color-warning, #b45309);
	}

	.btn-primary {
		display: inline-block;
		padding: 0.6rem 1.4rem;
		background: var(--color-primary);
		border: none;
		border-radius: 8px;
		color: #fff;
		font-size: 0.9rem;
		font-weight: 600;
		cursor: pointer;
		text-decoration: none;
		margin-top: 0.5rem;
	}

	.btn-primary:hover:not(:disabled) {
		filter: brightness(1.08);
	}

	.btn-primary:disabled {
		opacity: 0.7;
		cursor: default;
	}

	.error {
		color: var(--color-danger, #b00020);
		font-size: 0.8rem;
	}

	.btn-secondary {
		display: inline-block;
		padding: 0.6rem 1.4rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		color: var(--color-text);
		font-size: 0.9rem;
		cursor: pointer;
		text-decoration: none;
		margin-top: 0.5rem;
	}

	.btn-secondary:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
</style>
