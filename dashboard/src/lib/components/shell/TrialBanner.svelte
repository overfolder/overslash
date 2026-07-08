<script lang="ts">
	import type { TrialSummary } from '$lib/session';

	let { trial, isAdmin = false }: { trial: TrialSummary; isAdmin?: boolean } = $props();

	const expired = $derived(trial.status === 'expired');
	// Warn tone once the trial is nearly up (or an admin should act).
	const urgent = $derived(expired || trial.days_remaining <= 5);

	const daysLabel = $derived(
		trial.days_remaining === 1 ? '1 day' : `${trial.days_remaining} days`
	);

	const endDate = $derived(
		new Date(trial.ends_at * 1000).toLocaleDateString(undefined, {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		})
	);
</script>

<div class="trial-banner" class:urgent role="status" aria-live="polite">
	<span class="badge">{expired ? 'Trial expired' : 'Trial'}</span>
	<span class="message">
		{#if expired}
			Your free trial ended on {endDate}.
			{#if isAdmin}
				<a href="/billing/new-team">Add billing</a> to keep your team's shared setup.
			{:else}
				Ask an org admin to add billing.
			{/if}
		{:else}
			<strong>{daysLabel} left</strong> in your free trial (ends {endDate}).
			{#if isAdmin}
				<a href="/billing/new-team">Add billing</a> any time.
			{/if}
		{/if}
	</span>
</div>

<style>
	.trial-banner {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		padding: 0.55rem 1rem;
		font-size: 0.85rem;
		color: var(--color-text);
		background: var(--color-info-soft, var(--neutral-100));
		border-bottom: 1px solid var(--color-border);
	}
	.trial-banner.urgent {
		background: var(--color-warning-soft);
		border-bottom-color: var(--color-warning-border, var(--color-warning));
	}
	.badge {
		flex-shrink: 0;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.03em;
		padding: 0.1rem 0.45rem;
		border-radius: var(--radius-pill, 999px);
		background: var(--badge-bg-success, var(--neutral-200));
		color: var(--color-text);
	}
	.urgent .badge {
		background: var(--badge-bg-warning, var(--color-warning));
		color: var(--color-warning-on, #3a2a00);
	}
	.message {
		min-width: 0;
	}
	.message a {
		color: var(--color-primary, var(--primary-600));
		font-weight: 600;
		text-decoration: none;
	}
	.message a:hover {
		text-decoration: underline;
	}
</style>
