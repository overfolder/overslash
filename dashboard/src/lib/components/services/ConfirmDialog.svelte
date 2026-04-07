<script lang="ts">
	let {
		open,
		title,
		message,
		confirmLabel = 'Confirm',
		cancelLabel = 'Cancel',
		danger = false,
		onconfirm,
		oncancel
	}: {
		open: boolean;
		title: string;
		message: string;
		confirmLabel?: string;
		cancelLabel?: string;
		danger?: boolean;
		onconfirm: () => void;
		oncancel: () => void;
	} = $props();
</script>

{#if open}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="backdrop" onclick={oncancel}>
		<div
			class="dialog"
			role="dialog"
			tabindex="-1"
			aria-modal="true"
			aria-labelledby="confirm-title"
			onclick={(e) => e.stopPropagation()}
		>
			<h2 id="confirm-title">{title}</h2>
			<p>{message}</p>
			<div class="actions">
				<button type="button" class="btn" onclick={oncancel}>{cancelLabel}</button>
				<button
					type="button"
					class="btn"
					class:danger
					class:primary={!danger}
					onclick={onconfirm}>{confirmLabel}</button
				>
			</div>
		</div>
	</div>
{/if}

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}
	.dialog {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.5rem;
		max-width: 440px;
		width: 90%;
		box-shadow: 0 20px 50px rgba(0, 0, 0, 0.25);
	}
	h2 {
		margin: 0 0 0.5rem;
		font-size: 1.1rem;
	}
	p {
		color: var(--color-text-muted);
		margin: 0 0 1.25rem;
		font-size: 0.9rem;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}
	.btn {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.btn.danger {
		background: #dc2626;
		color: white;
		border-color: #dc2626;
	}
</style>
