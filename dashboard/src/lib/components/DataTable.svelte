<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Column {
		key: string;
		label: string;
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	let {
		items = [],
		columns = [],
		loading = false,
		emptyMessage = 'No items found.',
		cell
	}: {
		items: any[];
		columns: Column[];
		loading?: boolean;
		emptyMessage?: string;
		cell?: Snippet<[{ item: any; column: Column; value: unknown }]>;
	} = $props();
</script>

{#if loading}
	<div class="loading">
		<div class="spinner"></div>
		<span>Loading...</span>
	</div>
{:else if items.length === 0}
	<div class="empty">{emptyMessage}</div>
{:else}
	<div class="table-wrap">
		<table>
			<thead>
				<tr>
					{#each columns as col}
						<th>{col.label}</th>
					{/each}
				</tr>
			</thead>
			<tbody>
				{#each items as item}
					<tr>
						{#each columns as col}
							<td>
								{#if cell}
									{@render cell({ item, column: col, value: item[col.key] })}
								{:else}
									{item[col.key] ?? '—'}
								{/if}
							</td>
						{/each}
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<style>
	.table-wrap {
		overflow-x: auto;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.9rem;
	}

	thead th {
		text-align: left;
		padding: 0.6rem 0.75rem;
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		border-bottom: 1px solid var(--color-border);
	}

	tbody td {
		padding: 0.6rem 0.75rem;
		border-bottom: 1px solid var(--color-border);
		color: var(--color-text);
	}

	tbody tr:hover {
		background: rgba(99, 102, 241, 0.05);
	}

	.loading {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 1.5rem;
		color: var(--color-text-muted);
	}

	.spinner {
		width: 18px;
		height: 18px;
		border: 2px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.empty {
		padding: 2rem;
		text-align: center;
		color: var(--color-text-muted);
		font-size: 0.9rem;
	}
</style>
