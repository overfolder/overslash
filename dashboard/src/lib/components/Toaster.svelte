<script lang="ts">
	import { toasts, dismissToast } from '$lib/stores/toasts.svelte';
</script>

{#if toasts.items.length > 0}
	<div class="toast-zone" role="status" aria-live="polite">
		{#each toasts.items as t (t.id)}
			<button
				type="button"
				class="toast {t.kind}"
				onclick={() => dismissToast(t.id)}
				title="Dismiss"
			>
				<span class="dot"></span>
				<span class="msg">{t.message}</span>
			</button>
		{/each}
	</div>
{/if}

<style>
	.toast-zone {
		position: fixed;
		bottom: 24px;
		right: 24px;
		display: flex;
		flex-direction: column;
		gap: 8px;
		z-index: 100;
		pointer-events: none;
	}
	.toast {
		pointer-events: auto;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		box-shadow: var(--shadow-md);
		padding: 10px 14px;
		display: flex;
		align-items: center;
		gap: 8px;
		font: var(--text-label);
		color: var(--color-text);
		text-align: left;
		cursor: pointer;
		max-width: min(420px, calc(100vw - 48px));
		animation: toastIn 0.15s ease;
	}
	.toast .msg {
		min-width: 0;
		overflow-wrap: anywhere;
	}
	.toast .dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex: none;
		background: var(--color-text-muted);
	}
	.toast.success {
		border-color: rgba(33, 184, 107, 0.3);
	}
	.toast.success .dot {
		background: var(--color-success);
	}
	.toast.error {
		border-color: rgba(229, 56, 54, 0.3);
	}
	.toast.error .dot {
		background: var(--color-danger);
	}
	@keyframes toastIn {
		from {
			opacity: 0;
			transform: translateY(8px);
		}
		to {
			opacity: 1;
			transform: none;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.toast {
			animation: none;
		}
	}
	@media (max-width: 768px) {
		.toast-zone {
			left: 16px;
			right: 16px;
			bottom: 16px;
		}
	}
</style>
