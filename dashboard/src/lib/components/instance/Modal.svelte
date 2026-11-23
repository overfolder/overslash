<script lang="ts">
	// Dialog shell shared by the panel's modals: title + subtitle, body, a
	// footer of actions, and the step-up note every instance mutation carries.
	import type { Snippet } from 'svelte';

	let {
		title,
		sub,
		error = null,
		onClose,
		children,
		footer
	}: {
		title: string;
		sub?: Snippet;
		error?: string | null;
		onClose: () => void;
		children: Snippet;
		footer: Snippet;
	} = $props();

	function onKey(e: KeyboardEvent) {
		if (e.key === 'Escape') onClose();
	}
</script>

<svelte:window onkeydown={onKey} />

<!-- Escape closes through the window listener above. -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<div class="backdrop" role="presentation" onclick={onClose}>
	<div
		class="modal"
		role="dialog"
		aria-modal="true"
		aria-label={title}
		tabindex="-1"
		onclick={(e) => e.stopPropagation()}
	>
		<header>
			<div>
				<h2>{title}</h2>
				{#if sub}<div class="sub">{@render sub()}</div>{/if}
			</div>
			<button class="x" type="button" aria-label="Close" onclick={onClose}>✕</button>
		</header>
		<div class="body">
			{@render children()}
			<div class="stepup">
				<svg
					width="14"
					height="14"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="1.5"
					stroke-linecap="round"
					stroke-linejoin="round"
					aria-hidden="true"
					><path
						d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
					/></svg
				>
				<span
					>Saving asks you to sign in again if your last sign-in is too old
					(<code>ADMIN_STEP_UP_MAX_AGE_SECS</code>). The change is written to the instance audit.</span
				>
			</div>
			{#if error}<p class="error" role="alert">{error}</p>{/if}
		</div>
		<footer>{@render footer()}</footer>
	</div>
</div>

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: 16px;
	}
	.modal {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		width: 520px;
		max-width: 100%;
		max-height: calc(100vh - 32px);
		overflow-y: auto;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
	}
	header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 12px;
		padding: 20px 24px 0;
	}
	h2 {
		margin: 0;
		font-weight: 700;
		font-size: 16px;
		color: var(--color-text-heading);
	}
	.sub {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		margin-top: 2px;
	}
	.x {
		border: 0;
		background: transparent;
		color: var(--color-text-muted);
		width: 32px;
		height: 32px;
		border-radius: 8px;
		cursor: pointer;
		font-size: 14px;
		flex: none;
	}
	.x:hover {
		background: color-mix(in srgb, var(--color-text) 6%, transparent);
		color: var(--color-text);
	}
	.body {
		display: flex;
		flex-direction: column;
		gap: 14px;
		padding: 16px 24px;
	}
	.stepup {
		display: flex;
		gap: 8px;
		align-items: flex-start;
		font: var(--text-body-sm);
		color: var(--color-text-secondary);
		background: var(--neutral-50);
		border: 1px solid var(--color-border-subtle);
		border-radius: 8px;
		padding: 10px 12px;
	}
	.stepup svg {
		flex: none;
		margin-top: 1px;
	}
	.error {
		margin: 0;
		color: var(--color-danger);
		font: var(--text-body-sm);
	}
	footer {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
		padding: 0 24px 20px;
	}
	footer :global(.btn) {
		padding: 9px 16px;
		border-radius: 8px;
		font: var(--text-body-medium);
		cursor: pointer;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
	}
	footer :global(.btn:disabled) {
		opacity: 0.5;
		cursor: not-allowed;
	}
	footer :global(.btn-primary) {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	footer :global(.btn-danger) {
		background: var(--color-danger);
		border-color: var(--color-danger);
		color: #fff;
	}
</style>
