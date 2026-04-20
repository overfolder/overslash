<script lang="ts">
	import ApprovalResolver from './ApprovalResolver.svelte';
	import type { ApprovalResponse } from '$lib/session';

	let {
		open,
		approval,
		onClose,
		onResolved
	}: {
		open: boolean;
		approval: ApprovalResponse | null;
		onClose: () => void;
		onResolved?: (a: ApprovalResponse) => void;
	} = $props();

	function handleKey(e: KeyboardEvent) {
		if (e.key === 'Escape') onClose();
	}

	function handleBackdrop(e: MouseEvent) {
		if (e.target === e.currentTarget) onClose();
	}
</script>

<svelte:window onkeydown={handleKey} />

{#if open && approval}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="backdrop" onclick={handleBackdrop} onkeydown={handleKey}>
		<div
			class="card"
			role="dialog"
			aria-modal="true"
			aria-labelledby="approval-modal-title"
			tabindex="-1"
		>
			<div class="header">
				<h2 id="approval-modal-title">Approval Request</h2>
				<button class="close" aria-label="Close" onclick={onClose}>×</button>
			</div>
			<p class="summary">{approval.action_summary}</p>
			<ApprovalResolver
				{approval}
				compact
				onResolved={(updated) => {
					onResolved?.(updated);
				}}
			/>
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
		padding: var(--space-4, 16px);
	}
	.card {
		background: var(--color-surface, #fff);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 24px 28px;
		max-width: 560px;
		width: 100%;
		max-height: calc(100vh - 64px);
		overflow-y: auto;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	.header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}
	h2 {
		margin: 0;
		font-weight: 700;
		font-size: 16px;
		line-height: 1.25;
		color: var(--color-text-heading, var(--color-text));
	}
	.close {
		background: none;
		border: none;
		font-size: 22px;
		line-height: 1;
		color: var(--color-text-muted);
		cursor: pointer;
		padding: 0 4px;
	}
	.close:hover {
		color: var(--color-text);
	}
	.summary {
		margin: 0;
		font-size: 0.9rem;
		color: var(--color-text);
	}
</style>
