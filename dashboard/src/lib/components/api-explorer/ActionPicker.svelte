<script lang="ts">
	import type { ActionSummary } from '$lib/types';
	import HttpMethodBadge from './HttpMethodBadge.svelte';

	let {
		actions,
		value,
		loading = false,
		onchange
	}: {
		actions: ActionSummary[];
		value: string | null;
		loading?: boolean;
		onchange: (v: string) => void;
	} = $props();

	const sorted = $derived([...actions].sort((a, b) => a.key.localeCompare(b.key)));
	const selected = $derived(sorted.find((a) => a.key === value) ?? null);
</script>

<label class="wrap">
	<span class="label">Action</span>
	<div class="row">
		<select
			class="control"
			value={value ?? ''}
			disabled={loading || actions.length === 0}
			onchange={(e) => onchange((e.currentTarget as HTMLSelectElement).value)}
		>
			<option value="" disabled>
				{loading ? 'Loading actions…' : actions.length === 0 ? 'No actions available' : 'Select an action…'}
			</option>
			{#each sorted as a (a.key)}
				<option value={a.key}>
					{a.key} — {a.description || a.path} [{a.risk}]
				</option>
			{/each}
		</select>
		{#if selected}
			<div class="badge-slot">
				<HttpMethodBadge method={selected.method} />
			</div>
		{/if}
	</div>
</label>

<style>
	.wrap {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.label {
		font: var(--text-label);
		color: var(--color-text);
	}
	.row {
		position: relative;
		display: flex;
		align-items: center;
	}
	.control {
		width: 100%;
		padding: 0.55rem 0.75rem;
		padding-right: 4.5rem;
		font: inherit;
		font-size: 0.88rem;
		color: var(--color-text);
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
	}
	.control:focus {
		outline: 2px solid var(--color-primary);
		outline-offset: -1px;
	}
	.badge-slot {
		position: absolute;
		right: 2rem;
		pointer-events: none;
	}
</style>
