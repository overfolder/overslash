<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { ApiError, session } from '$lib/session';

	let view: 'redirecting' | 'error' = 'redirecting';
	let errorMsg: string | null = null;

	onMount(async () => {
		const orgId = $page.url.searchParams.get('org_id');
		if (!orgId) {
			view = 'error';
			errorMsg = 'No org ID specified.';
			return;
		}
		try {
			const res = await session.post<{ url: string }>('/v1/billing/portal', { org_id: orgId });
			window.location.href = res.url;
		} catch (err) {
			view = 'error';
			if (err instanceof ApiError) {
				const body = err.body as { error?: string } | undefined;
				errorMsg = body?.error ?? `Error ${err.status}`;
			} else {
				errorMsg = 'Could not open billing portal.';
			}
		}
	});
</script>

<svelte:head>
	<title>Billing portal — Overslash</title>
</svelte:head>

<div class="page">
	<div class="card">
		{#if view === 'redirecting'}
			<div class="spinner" aria-label="Opening billing portal…"></div>
			<p>Opening Stripe billing portal…</p>
		{:else}
			<div class="warn">⚠</div>
			<p class="error">{errorMsg}</p>
			<a href="/org" class="btn-secondary">Back to settings</a>
		{/if}
	</div>
</div>

<style>
	.page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--color-bg);
	}

	.card {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 1rem;
		padding: 2rem;
	}

	p {
		font-size: 0.9rem;
		color: var(--color-text-muted);
		margin: 0;
	}

	.error {
		color: var(--color-danger, #b00020);
	}

	.warn {
		font-size: 2rem;
		color: var(--color-warning, #b45309);
	}

	.spinner {
		width: 2rem;
		height: 2rem;
		border: 3px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.btn-secondary {
		padding: 0.5rem 1.2rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 0.85rem;
		cursor: pointer;
		text-decoration: none;
	}

	.btn-secondary:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
</style>
