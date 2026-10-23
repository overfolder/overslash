<script lang="ts">
	import {
		stepUp,
		dismissStepUp,
		type StepUpChallenge,
		type StepUpProvider
	} from '#lib/stores/stepUp.svelte.ts';

	const challenge = $derived(stepUp.pending);

	function minutes(secs: number): string {
		const m = Math.round(secs / 60);
		return m === 1 ? '1 minute' : `${m} minutes`;
	}

	function explain(c: StepUpChallenge): string {
		switch (c.reason) {
			case 'stale':
				return `Admin changes need a sign-in from the last ${minutes(c.max_age_secs)}. Sign in again to continue.`;
			case 'provider_not_allowed':
				return "Admin changes in this org need a sign-in through one of the org's own identity providers.";
			default:
				return "Admin changes in this org need a sign-in through an identity provider, so its multi-factor check applies. An email link isn't enough.";
		}
	}

	/** The login path, returning to this page afterwards. An IdP login takes
	 * `next`; the email-link fallback goes through the login page's `return_to`. */
	function href(p: StepUpProvider): string {
		const here = encodeURIComponent(window.location.pathname + window.location.search);
		return p.key === 'email'
			? `${p.login_path}&return_to=${here}`
			: `${p.login_path}&next=${here}`;
	}
</script>

{#if challenge}
	<div
		class="backdrop"
		role="dialog"
		aria-modal="true"
		aria-labelledby="su-title"
		data-testid="step-up-modal"
	>
		<div class="card">
			<h2 id="su-title">Confirm it's you</h2>
			<p>{explain(challenge)}</p>
			{#if challenge.providers.length > 0}
				<div class="providers">
					{#each challenge.providers as p (p.key)}
						<a class="btn btn-primary" href={href(p)}>
							{p.key === 'email' ? 'Sign in again with an email link' : `Continue with ${p.display_name}`}
						</a>
					{/each}
				</div>
			{:else}
				<p class="error" role="alert">
					This deployment offers no way to sign in again. Ask its operator to configure an identity
					provider.
				</p>
			{/if}
			<p class="hint">You'll come back to this page. Then repeat the change.</p>
			<div class="actions">
				<button class="btn" onclick={dismissStepUp}>Cancel</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: var(--space-4);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 24px 28px;
		max-width: 400px;
		width: 100%;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	h2 {
		margin: 0;
		font-weight: 700;
		font-size: 16px;
		line-height: 1.25;
		color: var(--color-text-heading);
	}
	p {
		margin: 0;
		font: var(--text-body);
		color: var(--color-text-secondary, var(--color-text));
	}
	p.hint {
		font-size: 13px;
		color: var(--color-text-muted);
	}
	p.error {
		color: var(--color-danger, #b91c1c);
		font-size: 13px;
	}
	.providers {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
	}
	.btn {
		padding: 10px 16px;
		border-radius: 8px;
		font: var(--text-body-medium);
		cursor: pointer;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		text-align: center;
		text-decoration: none;
	}
	.btn-primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
</style>
