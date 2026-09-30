<script lang="ts">
	import type { Snippet } from 'svelte';

	// Disclosure for the instance form's non-essential fields: endpoint and
	// config values that have a default most operators keep. The parent opens
	// it up front when one of them already holds an override, so a
	// non-default value is never hidden.
	let {
		open = $bindable(false),
		count,
		children
	}: {
		open?: boolean;
		/** How many fields are inside, shown on the toggle. */
		count?: number;
		children: Snippet;
	} = $props();
</script>

<div class="more-options">
	<button
		type="button"
		class="toggle"
		aria-expanded={open}
		onclick={() => (open = !open)}
	>
		<span class="chevron" aria-hidden="true">{open ? '▾' : '▸'}</span>
		{open ? 'Hide more options' : 'Show more options'}
		{#if count}<span class="count">{count}</span>{/if}
	</button>
	{#if open}
		<div class="body">
			{@render children()}
		</div>
	{/if}
</div>

<style>
	.more-options {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.toggle {
		align-self: flex-start;
		display: inline-flex;
		align-items: center;
		gap: 6px;
		background: none;
		border: none;
		padding: 0;
		font: inherit;
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--color-primary);
		cursor: pointer;
	}
	.toggle:hover {
		text-decoration: underline;
	}
	.chevron {
		width: 0.8em;
	}
	.count {
		font-size: 0.7rem;
		font-weight: 600;
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		padding: 0 5px;
	}
	.body {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		padding-left: 0.9rem;
		border-left: 2px solid var(--color-border);
	}
</style>
