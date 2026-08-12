<script lang="ts">
	import { isRiskLevel } from '$lib/types';

	let {
		risk,
		onclick
	}: {
		/** `read` | `write` | `delete`, or null for events off the gated path. */
		risk: string | null;
		/** Adds a `risk =` filter. Omit to render a plain, inert pill. */
		onclick?: (risk: string) => void;
	} = $props();

	// Deliberately not the approvals `low|med|high` vocabulary: this is the
	// `Risk` ladder the row actually stores, and calling a delete "high risk"
	// here would invent a judgement the column does not make. Same tone tokens,
	// so the two read as one system.
	const tone = $derived(
		risk === 'delete' ? 'danger' : risk === 'write' ? 'warning' : 'success'
	);
	const known = $derived(risk !== null && isRiskLevel(risk));
</script>

{#if !known}
	<!-- Control-plane events carry no risk. An em dash says "not applicable"
	     where an empty cell would read as a rendering failure. -->
	<span class="none" title="Not a gated action call">—</span>
{:else if onclick}
	<button
		type="button"
		class="badge tone-{tone}"
		title={`Filter by risk = ${risk}`}
		onclick={(e) => {
			e.stopPropagation();
			onclick(risk!);
		}}>{risk}</button
	>
{:else}
	<span class="badge tone-{tone}">{risk}</span>
{/if}

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border: 0;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 500;
		line-height: 1.4;
		white-space: nowrap;
	}
	button.badge {
		cursor: pointer;
		font-family: inherit;
	}
	button.badge:hover {
		outline: 1px solid currentColor;
	}
	.tone-success {
		background: var(--badge-bg-success);
		color: var(--color-success);
	}
	.tone-warning {
		background: var(--badge-bg-warning);
		color: var(--color-warning);
	}
	.tone-danger {
		background: var(--badge-bg-danger);
		color: var(--color-danger);
	}
	.none {
		color: var(--color-text-muted);
	}
</style>
