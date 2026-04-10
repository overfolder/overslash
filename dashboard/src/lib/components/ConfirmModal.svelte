<script lang="ts">
	let {
		open,
		title,
		message,
		confirmLabel = 'Confirm',
		cancelLabel = 'Cancel',
		destructive = false,
		busy = false,
		onConfirm,
		onCancel
	}: {
		open: boolean;
		title: string;
		message: string;
		confirmLabel?: string;
		cancelLabel?: string;
		destructive?: boolean;
		busy?: boolean;
		onConfirm: () => void;
		onCancel: () => void;
	} = $props();
</script>

{#if open}
	<div class="backdrop" role="dialog" aria-modal="true" aria-labelledby="cm-title">
		<div class="card">
			<h2 id="cm-title">{title}</h2>
			<p>{message}</p>
			<div class="actions">
				<button class="btn" disabled={busy} onclick={onCancel}>{cancelLabel}</button>
				<button
					class="btn {destructive ? 'btn-danger' : 'btn-primary'}"
					disabled={busy}
					onclick={onConfirm}
				>
					{busy ? 'Working…' : confirmLabel}
				</button>
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
		max-width: 360px;
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
	.actions {
		display: flex;
		gap: 8px;
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
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	.btn-danger {
		background: var(--color-danger);
		border-color: var(--color-danger);
		color: #fff;
	}
</style>
