<script lang="ts">
	import type { Group, GroupGrantPick } from '$lib/api/groups';

	let {
		groups,
		excludeIds = [],
		busy = false,
		addLabel = 'Add group',
		onadd
	}: {
		groups: Group[];
		/** Group ids already granted — hidden from the picker. */
		excludeIds?: string[];
		busy?: boolean;
		addLabel?: string;
		onadd: (pick: GroupGrantPick) => void;
	} = $props();

	let groupId = $state('');
	let accessLevel = $state<'read' | 'write' | 'admin'>('read');
	let autoApprove = $state(false);

	// Myself groups are auto-managed and only ever grant their owner's own
	// services — the API rejects anything else, so never offer them here.
	const available = $derived(
		groups.filter((g) => g.system_kind !== 'self' && !excludeIds.includes(g.id))
	);

	function optionLabel(g: Group): string {
		return g.is_member === false ? `${g.name} (you're not a member)` : g.name;
	}

	function add() {
		if (!groupId) return;
		onadd({ group_id: groupId, access_level: accessLevel, auto_approve_reads: autoApprove });
		groupId = '';
		accessLevel = 'read';
		autoApprove = false;
	}
</script>

<div class="add-group">
	<label class="field">
		<span class="label">Group</span>
		<select bind:value={groupId}>
			<option value="">— Select a group —</option>
			{#each available as g (g.id)}
				<option value={g.id}>{optionLabel(g)}</option>
			{/each}
		</select>
	</label>
	<label class="field">
		<span class="label">Access</span>
		<select bind:value={accessLevel}>
			<option value="read">Read</option>
			<option value="write">Write</option>
			<option value="admin">Admin</option>
		</select>
	</label>
	<label class="inline-field">
		<input type="checkbox" bind:checked={autoApprove} />
		<span>Auto-approve reads</span>
	</label>
	<button type="button" class="btn primary" onclick={add} disabled={!groupId || busy}>
		{busy ? 'Adding…' : addLabel}
	</button>
</div>

<style>
	.add-group {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-end;
		gap: 0.75rem;
		padding-top: 0.5rem;
		border-top: 1px dashed var(--color-border);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		min-width: 180px;
	}
	.field select {
		padding: 0.5rem 0.7rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: inherit;
		font: inherit;
		font-size: 0.9rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.inline-field {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		font-size: 0.85rem;
	}
	.btn {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
		font-size: 0.85rem;
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
</style>
