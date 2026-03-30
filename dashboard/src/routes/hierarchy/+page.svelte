<script lang="ts">
	import { getIdentities, getOrg, createIdentity, updateIdentity, deleteIdentity } from '$lib/api';
	import type { Identity, Org } from '$lib/types';
	import TreeNode from '../../components/TreeNode.svelte';
	import InlineForm from '../../components/InlineForm.svelte';
	import ConfirmDialog from '../../components/ConfirmDialog.svelte';

	let identities = $state<Identity[]>([]);
	let org = $state<Org | null>(null);
	let loading = $state(true);

	let expandedNodes = $state(new Set<string>());
	let editingId = $state<string | null>(null);
	let creatingUnder = $state<string | null>(null);
	let showApiKeysFor = $state<string | null>(null);
	let deletingIdentity = $state<Identity | null>(null);

	// Build tree: group identities by parent_id
	const childMap = $derived.by(() => {
		const map = new Map<string | null, Identity[]>();
		for (const identity of identities) {
			const key = identity.parent_id;
			if (!map.has(key)) map.set(key, []);
			map.get(key)!.push(identity);
		}
		return map;
	});

	const rootIdentities = $derived(childMap.get(null) || []);

	async function loadData() {
		loading = true;
		try {
			const [ids, o] = await Promise.all([getIdentities(), getOrg()]);
			identities = ids;
			org = o;
		} finally {
			loading = false;
		}
	}

	function toggleExpand(id: string) {
		const next = new Set(expandedNodes);
		if (next.has(id)) {
			next.delete(id);
		} else {
			next.add(id);
		}
		expandedNodes = next;
	}

	function startEdit(id: string) {
		editingId = id;
		creatingUnder = null;
	}

	function cancelEdit() {
		editingId = null;
	}

	async function saveEdit(id: string, name: string) {
		await updateIdentity(id, { name });
		editingId = null;
		await refreshIdentities();
	}

	function startCreate(parentId: string) {
		creatingUnder = parentId;
		editingId = null;
	}

	function cancelCreate() {
		creatingUnder = null;
	}

	async function saveCreate(name: string, kind: string, parentId: string) {
		const actualParentId = parentId === 'ROOT' ? null : parentId;
		const created = await createIdentity({
			name,
			kind,
			parent_id: actualParentId
		});
		creatingUnder = null;
		await refreshIdentities();
		// Auto-expand the parent so the new child is visible
		if (actualParentId) {
			const next = new Set(expandedNodes);
			next.add(actualParentId);
			expandedNodes = next;
		}
	}

	function confirmDelete(identity: Identity) {
		deletingIdentity = identity;
	}

	async function handleDelete() {
		if (!deletingIdentity) return;
		await deleteIdentity(deletingIdentity.id);
		deletingIdentity = null;
		await refreshIdentities();
	}

	function toggleApiKeys(id: string) {
		showApiKeysFor = showApiKeysFor === id ? null : id;
	}

	async function refreshIdentities() {
		identities = await getIdentities();
	}

	$effect(() => {
		loadData();
	});
</script>

<div class="hierarchy-page">
	<div class="page-header">
		<h1>Identity Hierarchy</h1>
	</div>

	{#if loading}
		<p class="muted">Loading...</p>
	{:else if org}
		<div class="tree-container">
			<!-- Org root node -->
			<div class="org-node">
				<span class="org-icon">{'\u{1F3E2}'}</span>
				<span class="org-name">{org.name}</span>
				<span class="org-badge">ORG</span>
				<button
					class="action-btn"
					title="Add user"
					data-testid="add-root-identity"
					onclick={() => startCreate('ROOT')}
				>
					+
				</button>
			</div>

			{#if creatingUnder === null && !editingId}
				<!-- Handled below -->
			{/if}

			<div class="tree-root">
				{#if creatingUnder === 'ROOT'}
					<div class="create-root-indent">
						<InlineForm
							parentKind="org"
							onsave={(name, kind) => saveCreate(name, kind, null)}
							oncancel={cancelCreate}
						/>
					</div>
				{/if}

				{#each rootIdentities as identity (identity.id)}
					<TreeNode
						{identity}
						{childMap}
						orgId={org.id}
						{expandedNodes}
						{editingId}
						{creatingUnder}
						{showApiKeysFor}
						onToggleExpand={toggleExpand}
						onStartEdit={startEdit}
						onCancelEdit={cancelEdit}
						onSaveEdit={saveEdit}
						onStartCreate={startCreate}
						onCancelCreate={cancelCreate}
						onSaveCreate={saveCreate}
						onDelete={confirmDelete}
						onToggleApiKeys={toggleApiKeys}
					/>
				{/each}
			</div>
		</div>
	{/if}
</div>

{#if deletingIdentity}
	<ConfirmDialog
		title="Delete {deletingIdentity.name}?"
		message="This will permanently delete this identity and all its children, including their API keys and permissions."
		onconfirm={handleDelete}
		oncancel={() => (deletingIdentity = null)}
	/>
{/if}

<style>
	.hierarchy-page {
		max-width: 900px;
	}

	.page-header {
		margin-bottom: 20px;
	}

	.page-header h1 {
		margin: 0;
		font-size: 22px;
		font-weight: 600;
	}

	.muted {
		color: #888;
	}

	.tree-container {
		background: #fff;
		border-radius: 8px;
		padding: 20px 24px;
		box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
	}

	.org-node {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 0;
		border-bottom: 1px solid #eee;
		margin-bottom: 8px;
	}

	.org-icon {
		font-size: 20px;
	}

	.org-name {
		font-weight: 600;
		font-size: 16px;
	}

	.org-badge {
		font-size: 11px;
		padding: 1px 8px;
		border-radius: 10px;
		font-weight: 600;
		background: #f3e8ff;
		color: #7c3aed;
		text-transform: uppercase;
	}

	.action-btn {
		background: none;
		border: 1px solid transparent;
		cursor: pointer;
		padding: 2px 8px;
		font-size: 16px;
		border-radius: 4px;
		color: #666;
		margin-left: 4px;
	}

	.action-btn:hover {
		background: #e8e8e8;
		border-color: #d0d0d0;
	}

	.tree-root {
		padding-left: 4px;
	}

	.create-root-indent {
		margin-left: 24px;
	}
</style>
