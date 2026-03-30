<script lang="ts">
	import type { Identity } from '$lib/types';
	import { updateIdentity } from '$lib/api';
	import InlineForm from './InlineForm.svelte';
	import ApiKeysPanel from './ApiKeysPanel.svelte';

	let {
		identity,
		childMap,
		orgId,
		expandedNodes,
		editingId,
		creatingUnder,
		showApiKeysFor,
		onToggleExpand,
		onStartEdit,
		onCancelEdit,
		onSaveEdit,
		onStartCreate,
		onCancelCreate,
		onSaveCreate,
		onDelete,
		onToggleApiKeys
	}: {
		identity: Identity;
		childMap: Map<string | null, Identity[]>;
		orgId: string;
		expandedNodes: Set<string>;
		editingId: string | null;
		creatingUnder: string | null;
		showApiKeysFor: string | null;
		onToggleExpand: (id: string) => void;
		onStartEdit: (id: string) => void;
		onCancelEdit: () => void;
		onSaveEdit: (id: string, name: string) => void;
		onStartCreate: (parentId: string) => void;
		onCancelCreate: () => void;
		onSaveCreate: (name: string, kind: string, parentId: string) => void;
		onDelete: (identity: Identity) => void;
		onToggleApiKeys: (id: string) => void;
	} = $props();

	let editName = $state(identity.name);
	let saving = $state(false);

	const children = $derived(childMap.get(identity.id) || []);
	const hasChildren = $derived(children.length > 0 || creatingUnder === identity.id);
	const isExpanded = $derived(expandedNodes.has(identity.id));
	const isEditing = $derived(editingId === identity.id);
	const isCreating = $derived(creatingUnder === identity.id);
	const showKeys = $derived(showApiKeysFor === identity.id);
	const kindIcon = $derived(identity.kind === 'user' ? '\u{1F464}' : '\u{1F916}');
	const parentKind = $derived(identity.kind as 'user' | 'agent');

	function handleEditKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter') handleSaveEdit();
		if (e.key === 'Escape') onCancelEdit();
	}

	async function handleSaveEdit() {
		if (!editName.trim() || editName.trim() === identity.name) {
			onCancelEdit();
			return;
		}
		saving = true;
		try {
			await onSaveEdit(identity.id, editName.trim());
		} finally {
			saving = false;
		}
	}
</script>

<div class="tree-node">
	<div class="node-row">
		<button
			class="expand-toggle"
			class:invisible={!hasChildren && children.length === 0}
			data-testid="expand-{identity.name}"
			onclick={() => onToggleExpand(identity.id)}
		>
			{#if hasChildren || children.length > 0}
				<span class="chevron" class:expanded={isExpanded}>{'\u25B6'}</span>
			{/if}
		</button>

		<span class="kind-icon">{kindIcon}</span>

		{#if isEditing}
			<input
				data-testid="edit-name-input"
				type="text"
				class="edit-input"
				bind:value={editName}
				onkeydown={handleEditKeydown}
				disabled={saving}
			/>
			<button
				data-testid="edit-save"
				class="btn btn-save"
				onclick={handleSaveEdit}
				disabled={saving}
			>
				Save
			</button>
			<button class="btn btn-cancel" onclick={onCancelEdit}>Cancel</button>
		{:else}
			<span class="node-name">{identity.name}</span>
			<span class="kind-badge {identity.kind}">{identity.kind}</span>

			<div class="node-actions">
				<button
					class="action-btn"
					title="Edit"
					data-testid="edit-{identity.name}"
					onclick={() => {
						editName = identity.name;
						onStartEdit(identity.id);
					}}
				>
					&#9998;
				</button>
				<button
					class="action-btn"
					title="Add child"
					data-testid="add-child-{identity.name}"
					onclick={() => {
						onStartCreate(identity.id);
						if (!isExpanded) onToggleExpand(identity.id);
					}}
				>
					+
				</button>
				<button
					class="action-btn"
					title="API Keys"
					data-testid="keys-{identity.name}"
					onclick={() => onToggleApiKeys(identity.id)}
				>
					&#128273;
				</button>
				<button
					class="action-btn action-delete"
					title="Delete"
					data-testid="delete-{identity.name}"
					onclick={() => onDelete(identity)}
				>
					&#128465;
				</button>
			</div>
		{/if}
	</div>

	{#if showKeys}
		<div class="panel-indent">
			<ApiKeysPanel identityId={identity.id} {orgId} />
		</div>
	{/if}

	{#if isExpanded}
		<div class="children">
			{#each children as child (child.id)}
				<svelte:self
					identity={child}
					{childMap}
					{orgId}
					{expandedNodes}
					{editingId}
					{creatingUnder}
					{showApiKeysFor}
					{onToggleExpand}
					{onStartEdit}
					{onCancelEdit}
					{onSaveEdit}
					{onStartCreate}
					{onCancelCreate}
					{onSaveCreate}
					{onDelete}
					{onToggleApiKeys}
				/>
			{/each}
			{#if isCreating}
				<div class="create-indent">
					<InlineForm
						{parentKind}
						onsave={(name, kind) => onSaveCreate(name, kind, identity.id)}
						oncancel={onCancelCreate}
					/>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.tree-node {
		margin-left: 20px;
	}

	.node-row {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 4px 0;
		min-height: 32px;
	}

	.expand-toggle {
		background: none;
		border: none;
		cursor: pointer;
		padding: 2px 4px;
		font-size: 10px;
		color: #666;
		width: 20px;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.expand-toggle.invisible {
		visibility: hidden;
	}

	.chevron {
		display: inline-block;
		transition: transform 0.15s;
	}

	.chevron.expanded {
		transform: rotate(90deg);
	}

	.kind-icon {
		font-size: 16px;
	}

	.node-name {
		font-weight: 500;
		font-size: 14px;
	}

	.kind-badge {
		font-size: 11px;
		padding: 1px 8px;
		border-radius: 10px;
		font-weight: 600;
		text-transform: uppercase;
	}

	.kind-badge.user {
		background: #dbeafe;
		color: #1d4ed8;
	}

	.kind-badge.agent {
		background: #dcfce7;
		color: #15803d;
	}

	.node-actions {
		display: flex;
		gap: 2px;
		margin-left: 8px;
		opacity: 0;
		transition: opacity 0.15s;
	}

	.node-row:hover .node-actions {
		opacity: 1;
	}

	.action-btn {
		background: none;
		border: 1px solid transparent;
		cursor: pointer;
		padding: 2px 6px;
		font-size: 14px;
		border-radius: 4px;
		color: #666;
	}

	.action-btn:hover {
		background: #e8e8e8;
		border-color: #d0d0d0;
	}

	.action-delete:hover {
		background: #fee2e2;
		color: #dc2626;
	}

	.edit-input {
		padding: 4px 8px;
		border: 1px solid #6366f1;
		border-radius: 4px;
		font-size: 14px;
		width: 200px;
		outline: none;
	}

	.btn {
		padding: 4px 10px;
		border-radius: 4px;
		font-size: 12px;
		cursor: pointer;
		border: none;
		font-weight: 500;
	}

	.btn-save {
		background: #6366f1;
		color: #fff;
	}

	.btn-cancel {
		background: #e0e0e0;
		color: #333;
	}

	.children {
		border-left: 1px solid #e0e0e0;
		margin-left: 9px;
	}

	.panel-indent {
		margin-left: 26px;
	}

	.create-indent {
		margin-left: 20px;
	}
</style>
