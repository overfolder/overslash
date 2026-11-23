<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { Tone } from './format.ts';

	let { tone = 'neutral', title, children }: { tone?: Tone; title?: string; children: Snippet } =
		$props();
</script>

<span class="badge {tone}" {title}>{@render children()}</span>

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font: var(--text-label-sm);
		padding: 2px 8px;
		border-radius: 9999px;
		white-space: nowrap;
		background: var(--badge-bg-neutral);
		color: var(--color-text-secondary);
	}
	.primary {
		background: var(--color-primary-bg);
		color: var(--color-primary);
	}
	.success {
		background: var(--badge-bg-success);
		color: var(--color-success);
	}
	.warning {
		background: var(--badge-bg-warning);
		color: var(--color-warning);
	}
	.error {
		background: var(--badge-bg-danger);
		color: var(--color-danger);
	}
</style>
