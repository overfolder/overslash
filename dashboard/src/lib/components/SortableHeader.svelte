<script lang="ts">
	import type { SortDir } from '$lib/sort';

	let {
		label,
		column,
		active,
		dir,
		onsort,
		align = 'left'
	}: {
		label: string;
		column: string;
		active: string;
		dir: SortDir;
		onsort: (column: string) => void;
		align?: 'left' | 'right';
	} = $props();

	const isActive = $derived(active === column);
	const ariaSort = $derived(
		isActive ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'
	);
</script>

<th aria-sort={ariaSort} class:right={align === 'right'}>
	<button type="button" class="sort-btn" class:active={isActive} onclick={() => onsort(column)}>
		<span>{label}</span>
		<span class="arrow" aria-hidden="true">{isActive ? (dir === 'asc' ? '▲' : '▼') : ''}</span>
	</button>
</th>

<style>
	th {
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		background: var(--color-bg);
		padding: 0;
	}
	.sort-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		width: 100%;
		padding: 0.7rem 0.9rem;
		font: inherit;
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: inherit;
		background: none;
		border: none;
		cursor: pointer;
		text-align: left;
	}
	.sort-btn:hover {
		color: var(--color-text);
	}
	.sort-btn.active {
		color: var(--color-text);
	}
	th.right .sort-btn {
		justify-content: flex-end;
		text-align: right;
	}
	.arrow {
		font-size: 0.65rem;
		line-height: 1;
	}
</style>
