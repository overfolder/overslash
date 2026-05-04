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
			class="frame"
			role="dialog"
			aria-modal="true"
			aria-labelledby="approval-modal-title"
			tabindex="-1"
		>
			<button class="close" aria-label="Close" onclick={onClose}>×</button>
			<h2 id="approval-modal-title" class="sr-only">Approval Request</h2>
			<ApprovalResolver {approval} {onResolved} />
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
		padding: 16px;
	}
	.frame {
		position: relative;
		width: 100%;
		max-width: 480px;
		max-height: calc(100vh - 32px);
		overflow-y: auto;
		border-radius: 12px;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
	}
	/* The ApprovalResolver provides its own card surface (border + bg);
	   the modal frame just sizes/positions it. We mask the corner radius
	   so the resolver's risk top bar doesn't overflow the frame. */
	.frame :global(.card) {
		border-radius: 12px;
	}
	.close {
		position: absolute;
		top: 8px;
		right: 8px;
		width: 32px;
		height: 32px;
		background: rgba(255, 255, 255, 0.85);
		border: 1px solid var(--color-border);
		border-radius: 50%;
		color: var(--color-text-muted);
		font-size: 18px;
		line-height: 1;
		cursor: pointer;
		z-index: 2;
		display: flex;
		align-items: center;
		justify-content: center;
	}
	:global([data-theme='dark']) .close {
		background: rgba(26, 27, 30, 0.85);
	}
	.close:hover {
		color: var(--color-text);
		background: var(--color-surface);
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}

	@media (max-width: 640px) {
		.backdrop {
			background: var(--color-bg);
			padding: 0;
		}
		.frame {
			max-width: none;
			max-height: 100vh;
			height: 100vh;
			border-radius: 0;
			box-shadow: none;
			overflow-y: auto;
		}
		.frame :global(.card) {
			max-width: none;
			border-radius: 0;
			border-left: 0;
			border-right: 0;
			min-height: 100vh;
		}
		.close {
			top: 12px;
			right: 12px;
		}
	}
</style>
