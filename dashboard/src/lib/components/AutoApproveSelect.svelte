<script lang="ts">
	// Auto-approval rides the same read < write < admin ladder as the grant's
	// access level, bounded by it — so the ceiling both gates the options and
	// decides how loud the warning needs to be. Rendering the out-of-range
	// rungs as disabled options (rather than hiding them) keeps the ladder
	// legible: you can see that `admin` exists and that this grant can't reach
	// it without raising Access first.
	export const LEVELS = ['none', 'read', 'write', 'admin'] as const;

	let {
		value,
		accessLevel,
		onchange,
		disabled = false,
		label = 'Auto-approve level'
	}: {
		value: string;
		/** The grant's access ceiling — levels above it can't be selected. */
		accessLevel: string;
		onchange: (next: string) => void;
		disabled?: boolean;
		label?: string;
	} = $props();

	const RANK: Record<string, number> = { none: 0, read: 1, write: 2, admin: 3 };

	function exceedsCeiling(level: string) {
		return (RANK[level] ?? 0) > (RANK[accessLevel] ?? 0);
	}

	// Unattended mutation is the thing worth flagging. Reads were always the
	// default, so they get no warning.
	let warning = $derived(
		value === 'admin'
			? 'Agents in this group run writes and deletes on this service with no approval prompt.'
			: value === 'write'
				? 'Agents in this group run writes on this service with no approval prompt.'
				: null
	);
</script>

<div class="auto-approve">
	<select
		class="level-select"
		{value}
		{disabled}
		aria-label={label}
		onchange={(e) => onchange((e.currentTarget as HTMLSelectElement).value)}
	>
		{#each LEVELS as level (level)}
			<option value={level} disabled={exceedsCeiling(level)}>{level}</option>
		{/each}
	</select>
	{#if warning}
		<p class="warn">{warning}</p>
	{/if}
</div>

<style>
	.auto-approve {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.level-select {
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		font: var(--text-body);
		color: var(--color-text);
		background: var(--color-surface);
	}
	.level-select:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.warn {
		margin: 0;
		max-width: 34ch;
		font: var(--text-body-sm);
		color: var(--color-warning);
	}
</style>
