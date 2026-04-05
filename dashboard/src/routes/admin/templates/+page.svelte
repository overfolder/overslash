<script lang="ts">
	import '$lib/admin.css';
	import { onMount } from 'svelte';
	import { session, formatApiError } from '$lib/session';
	import type { TemplateSummary } from '$lib/types';
	import DataTable from '$lib/components/DataTable.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';

	let templates: TemplateSummary[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);
	let searchQuery = $state('');
	let searchTimeout: ReturnType<typeof setTimeout> | undefined;

	// Create modal
	let showCreate = $state(false);
	let createForm = $state({
		key: '',
		display_name: '',
		description: '',
		category: '',
		hosts: '',
		auth: '[]',
		actions: '{}'
	});
	let createError: string | null = $state(null);
	let saving = $state(false);

	// Edit modal
	let showEdit = $state(false);
	let editTarget: TemplateSummary | null = $state(null);
	let editForm = $state({
		display_name: '',
		description: '',
		category: '',
		hosts: '',
		auth: '[]',
		actions: '{}'
	});
	let editError: string | null = $state(null);

	// Delete confirmation
	let showDelete = $state(false);
	let deleteTarget: TemplateSummary | null = $state(null);

	const columns = [
		{ key: 'key', label: 'Key' },
		{ key: 'display_name', label: 'Name' },
		{ key: 'category', label: 'Category' },
		{ key: 'tier', label: 'Tier' },
		{ key: 'action_count', label: 'Actions' },
		{ key: '_actions', label: '' }
	];

	async function load() {
		loading = true;
		error = null;
		try {
			templates = await session.get<TemplateSummary[]>('/v1/templates');
		} catch (e) {
			error = formatApiError(e);
		} finally {
			loading = false;
		}
	}

	async function search(q: string) {
		if (!q.trim()) {
			await load();
			return;
		}
		loading = true;
		try {
			templates = await session.get<TemplateSummary[]>(
				`/v1/templates/search?q=${encodeURIComponent(q)}`
			);
		} catch (e) {
			error = formatApiError(e);
		} finally {
			loading = false;
		}
	}

	function onSearch() {
		clearTimeout(searchTimeout);
		searchTimeout = setTimeout(() => search(searchQuery), 300);
	}

	async function handleCreate() {
		createError = null;
		saving = true;
		try {
			const hosts = createForm.hosts
				.split(',')
				.map((h) => h.trim())
				.filter(Boolean);
			const auth = JSON.parse(createForm.auth);
			const actions = JSON.parse(createForm.actions);
			await session.post('/v1/templates', {
				key: createForm.key,
				display_name: createForm.display_name,
				description: createForm.description,
				category: createForm.category,
				hosts,
				auth,
				actions,
				user_level: false
			});
			showCreate = false;
			createForm = {
				key: '',
				display_name: '',
				description: '',
				category: '',
				hosts: '',
				auth: '[]',
				actions: '{}'
			};
			await load();
		} catch (e) {
			if (e instanceof SyntaxError) {
				createError = 'Invalid JSON in auth or actions field';
			} else {
				createError = formatApiError(e);
			}
		} finally {
			saving = false;
		}
	}

	function openEdit(t: TemplateSummary) {
		editTarget = t;
		editForm = {
			display_name: t.display_name,
			description: t.description,
			category: t.category,
			hosts: t.hosts.join(', '),
			auth: '[]',
			actions: '{}'
		};
		editError = null;
		showEdit = true;
	}

	async function handleEdit() {
		if (!editTarget?.id) return;
		editError = null;
		saving = true;
		try {
			const hosts = editForm.hosts
				.split(',')
				.map((h) => h.trim())
				.filter(Boolean);
			await session.put(`/v1/templates/${editTarget.id}/manage`, {
				display_name: editForm.display_name,
				description: editForm.description,
				category: editForm.category,
				hosts
			});
			showEdit = false;
			await load();
		} catch (e) {
			editError = formatApiError(e);
		} finally {
			saving = false;
		}
	}

	function openDelete(t: TemplateSummary) {
		deleteTarget = t;
		showDelete = true;
	}

	async function handleDelete() {
		if (!deleteTarget?.id) return;
		try {
			await session.delete(`/v1/templates/${deleteTarget.id}/manage`);
			showDelete = false;
			await load();
		} catch (e) {
			error = formatApiError(e);
			showDelete = false;
		}
	}

	onMount(load);
</script>

<svelte:head>
	<title>Templates - Overslash Admin</title>
</svelte:head>

<div class="admin-page">
	<div class="page-header">
		<h1>Templates</h1>
		<button class="btn btn-primary" onclick={() => (showCreate = true)}>Create Template</button>
	</div>

	<div class="search-bar">
		<input
			type="text"
			placeholder="Search templates..."
			bind:value={searchQuery}
			oninput={onSearch}
		/>
	</div>

	{#if error}
		<div class="error-msg">{error}</div>
	{/if}

	<div class="card">
		<DataTable items={templates} {columns} {loading} emptyMessage="No templates found.">
			{#snippet cell({ item, column })}
				{#if column.key === 'tier'}
					<StatusBadge status={String(item.tier)} />
				{:else if column.key === '_actions'}
					{#if item.tier !== 'global'}
						<div class="row-actions">
							<button class="btn-sm" onclick={() => openEdit(item as unknown as TemplateSummary)}>Edit</button>
							<button class="btn-sm btn-danger" onclick={() => openDelete(item as unknown as TemplateSummary)}>Delete</button>
						</div>
					{:else}
						<span class="read-only">read-only</span>
					{/if}
				{:else}
					{item[column.key] ?? '—'}
				{/if}
			{/snippet}
		</DataTable>
	</div>
</div>

<!-- Create Modal -->
<Modal open={showCreate} title="Create Template" onclose={() => (showCreate = false)}>
	{#if createError}
		<div class="modal-error">{createError}</div>
	{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
		<div class="form-group">
			<label for="tpl-key">Key</label>
			<input id="tpl-key" type="text" bind:value={createForm.key} required placeholder="my-api" />
		</div>
		<div class="form-group">
			<label for="tpl-name">Display Name</label>
			<input id="tpl-name" type="text" bind:value={createForm.display_name} required placeholder="My API" />
		</div>
		<div class="form-group">
			<label for="tpl-desc">Description</label>
			<input id="tpl-desc" type="text" bind:value={createForm.description} placeholder="Optional description" />
		</div>
		<div class="form-group">
			<label for="tpl-cat">Category</label>
			<input id="tpl-cat" type="text" bind:value={createForm.category} placeholder="Dev Tools" />
		</div>
		<div class="form-group">
			<label for="tpl-hosts">Hosts (comma-separated)</label>
			<input id="tpl-hosts" type="text" bind:value={createForm.hosts} required placeholder="api.example.com" />
		</div>
		<div class="form-group">
			<label for="tpl-auth">Auth (JSON)</label>
			<textarea id="tpl-auth" bind:value={createForm.auth} rows="3"></textarea>
		</div>
		<div class="form-group">
			<label for="tpl-actions">Actions (JSON)</label>
			<textarea id="tpl-actions" bind:value={createForm.actions} rows="4"></textarea>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showCreate = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={saving}>
				{saving ? 'Creating...' : 'Create'}
			</button>
		</div>
	</form>
</Modal>

<!-- Edit Modal -->
<Modal open={showEdit} title="Edit Template" onclose={() => (showEdit = false)}>
	{#if editError}
		<div class="modal-error">{editError}</div>
	{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleEdit(); }}>
		<div class="form-group">
			<label for="edit-name">Display Name</label>
			<input id="edit-name" type="text" bind:value={editForm.display_name} required />
		</div>
		<div class="form-group">
			<label for="edit-desc">Description</label>
			<input id="edit-desc" type="text" bind:value={editForm.description} />
		</div>
		<div class="form-group">
			<label for="edit-cat">Category</label>
			<input id="edit-cat" type="text" bind:value={editForm.category} />
		</div>
		<div class="form-group">
			<label for="edit-hosts">Hosts (comma-separated)</label>
			<input id="edit-hosts" type="text" bind:value={editForm.hosts} />
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showEdit = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={saving}>
				{saving ? 'Saving...' : 'Save'}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete Confirmation -->
<Modal open={showDelete} title="Delete Template" onclose={() => (showDelete = false)}>
	<p class="confirm-text">Are you sure you want to delete template <strong>{deleteTarget?.key}</strong>?</p>
	<div class="modal-actions">
		<button class="btn btn-secondary" onclick={() => (showDelete = false)}>Cancel</button>
		<button class="btn btn-danger" onclick={handleDelete}>Delete</button>
	</div>
</Modal>

<style>
	.search-bar {
		margin-bottom: 1rem;
	}

	.search-bar input {
		width: 100%;
		max-width: 400px;
		padding: 0.5rem 0.75rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		color: var(--color-text);
		font-size: 0.9rem;
	}

	.search-bar input::placeholder {
		color: var(--color-text-muted);
	}
</style>
