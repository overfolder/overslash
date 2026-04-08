<script lang="ts">
	import type { TemplateSummary } from '$lib/types';
	import StatusBadge from './StatusBadge.svelte';

	let {
		template,
		selected = false,
		onselect
	}: {
		template: TemplateSummary;
		selected?: boolean;
		onselect: (t: TemplateSummary) => void;
	} = $props();
</script>

<button
	type="button"
	class="card"
	class:selected
	onclick={() => onselect(template)}
>
	<div class="head">
		<span class="name">{template.display_name}</span>
		<StatusBadge variant={template.tier} />
	</div>
	<div class="key">{template.key}</div>
	{#if template.description}
		<p class="desc">{template.description}</p>
	{/if}
	<div class="meta">
		<span>{template.action_count} action{template.action_count === 1 ? '' : 's'}</span>
		{#if template.category}
			<span>· {template.category}</span>
		{/if}
	</div>
</button>

<style>
	.card {
		text-align: left;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 1rem;
		cursor: pointer;
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		transition: border-color 0.1s ease, box-shadow 0.1s ease;
		font: inherit;
		color: inherit;
	}
	.card:hover {
		border-color: var(--color-primary, #6366f1);
	}
	.card.selected {
		border-color: var(--color-primary, #6366f1);
		box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.18);
	}
	.head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
	}
	.name {
		font-weight: 600;
		font-size: 0.95rem;
	}
	.key {
		font-family: var(--font-mono);
		font-size: 0.78rem;
		color: var(--color-text-muted);
	}
	.desc {
		margin: 0;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		display: -webkit-box;
		-webkit-line-clamp: 2;
		line-clamp: 2;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}
	.meta {
		font-size: 0.75rem;
		color: var(--color-text-muted);
		display: flex;
		gap: 0.4rem;
		margin-top: auto;
	}
</style>
