<script lang="ts">
	import '$lib/admin.css';
	import { onMount } from 'svelte';
	import { session, ApiError, formatApiError } from '$lib/session';
	import type { ServiceInstanceSummary, TemplateSummary } from '$lib/types';
	import DataTable from '$lib/components/DataTable.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';

	let services: ServiceInstanceSummary[] = $state([]);
	let templates: TemplateSummary[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	// Create modal
	let showCreate = $state(false);
	let createForm = $state({ template_key: '', name: '', status: 'active' });
	let createError: string | null = $state(null);
	let saving = $state(false);

	// Edit modal
	let showEdit = $state(false);
	let editTarget: ServiceInstanceSummary | null = $state(null);
	let editForm = $state({ name: '', connection_id: '', secret_name: '' });
	let editError: string | null = $state(null);

	// Delete
	let showDelete = $state(false);
	let deleteTarget: ServiceInstanceSummary | null = $state(null);

	const columns = [
		{ key: 'name', label: 'Name' },
		{ key: 'template_key', label: 'Template' },
		{ key: 'template_source', label: 'Source' },
		{ key: 'status', label: 'Status' },
		{ key: 'owner_identity_id', label: 'Scope' },
		{ key: '_actions', label: '' }
	];

	async function load() {
		loading = true;
		error = null;
		try {
			[services, templates] = await Promise.all([
				session.get<ServiceInstanceSummary[]>('/v1/services'),
				session.get<TemplateSummary[]>('/v1/templates')
			]);
		} catch (e) {
			error = formatApiError(e);
		} finally {
			loading = false;
		}
	}

	async function handleCreate() {
		createError = null;
		saving = true;
		try {
			await session.post('/v1/services', {
				template_key: createForm.template_key,
				name: createForm.name || undefined,
				status: createForm.status,
				user_level: false
			});
			showCreate = false;
			createForm = { template_key: '', name: '', status: 'active' };
			await load();
		} catch (e) {
			createError = formatApiError(e);
		} finally {
			saving = false;
		}
	}

	async function changeStatus(svc: ServiceInstanceSummary, newStatus: string) {
		try {
			await session.patch(`/v1/services/${svc.id}/status`, { status: newStatus });
			await load();
		} catch (e) {
			error = formatApiError(e);
		}
	}

	function openEdit(svc: ServiceInstanceSummary) {
		editTarget = svc;
		editForm = {
			name: svc.name,
			connection_id: svc.connection_id ?? '',
			secret_name: svc.secret_name ?? ''
		};
		editError = null;
		showEdit = true;
	}

	async function handleEdit() {
		if (!editTarget) return;
		editError = null;
		saving = true;
		try {
			await session.put(`/v1/services/${editTarget.id}/manage`, {
				name: editForm.name,
				connection_id: editForm.connection_id || null,
				secret_name: editForm.secret_name || null
			});
			showEdit = false;
			await load();
		} catch (e) {
			editError = formatApiError(e);
		} finally {
			saving = false;
		}
	}

	function openDelete(svc: ServiceInstanceSummary) {
		deleteTarget = svc;
		showDelete = true;
	}

	async function handleDelete() {
		if (!deleteTarget) return;
		try {
			await session.delete(`/v1/services/${deleteTarget.name}`);
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
	<title>Services - Overslash Admin</title>
</svelte:head>

<div class="admin-page">
	<div class="page-header">
		<h1>Services</h1>
		<button class="btn btn-primary" onclick={() => (showCreate = true)}>Create Service</button>
	</div>

	{#if error}
		<div class="error-msg">{error}</div>
	{/if}

	<div class="card">
		<DataTable items={services} {columns} {loading} emptyMessage="No service instances found.">
			{#snippet cell({ item, column })}
				{#if column.key === 'template_source'}
					<StatusBadge status={String(item.template_source)} />
				{:else if column.key === 'status'}
					<select
						class="status-select"
						value={String(item.status)}
						onchange={(e) => changeStatus(item as unknown as ServiceInstanceSummary, (e.target as HTMLSelectElement).value)}
					>
						<option value="draft">draft</option>
						<option value="active">active</option>
						<option value="archived">archived</option>
					</select>
				{:else if column.key === 'owner_identity_id'}
					<StatusBadge status={item.owner_identity_id ? 'user' : 'org'} />
				{:else if column.key === '_actions'}
					<div class="row-actions">
						<button class="btn-sm" onclick={() => openEdit(item as unknown as ServiceInstanceSummary)}>Edit</button>
						<button class="btn-sm btn-danger" onclick={() => openDelete(item as unknown as ServiceInstanceSummary)}>Delete</button>
					</div>
				{:else}
					{item[column.key] ?? '—'}
				{/if}
			{/snippet}
		</DataTable>
	</div>
</div>

<!-- Create Modal -->
<Modal open={showCreate} title="Create Service" onclose={() => (showCreate = false)}>
	{#if createError}
		<div class="modal-error">{createError}</div>
	{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
		<div class="form-group">
			<label for="svc-tpl">Template</label>
			<select id="svc-tpl" bind:value={createForm.template_key} required>
				<option value="">Select template...</option>
				{#each templates as tpl}
					<option value={tpl.key}>{tpl.display_name} ({tpl.key})</option>
				{/each}
			</select>
		</div>
		<div class="form-group">
			<label for="svc-name">Name (optional, defaults to template key)</label>
			<input id="svc-name" type="text" bind:value={createForm.name} placeholder="my-github" />
		</div>
		<div class="form-group">
			<label for="svc-status">Status</label>
			<select id="svc-status" bind:value={createForm.status}>
				<option value="active">active</option>
				<option value="draft">draft</option>
			</select>
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
<Modal open={showEdit} title="Edit Service" onclose={() => (showEdit = false)}>
	{#if editError}
		<div class="modal-error">{editError}</div>
	{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleEdit(); }}>
		<div class="form-group">
			<label for="edit-svc-name">Name</label>
			<input id="edit-svc-name" type="text" bind:value={editForm.name} required />
		</div>
		<div class="form-group">
			<label for="edit-conn">Connection ID</label>
			<input id="edit-conn" type="text" bind:value={editForm.connection_id} placeholder="UUID or empty" />
		</div>
		<div class="form-group">
			<label for="edit-secret">Secret Name</label>
			<input id="edit-secret" type="text" bind:value={editForm.secret_name} placeholder="Secret name or empty" />
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showEdit = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={saving}>
				{saving ? 'Saving...' : 'Save'}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete -->
<Modal open={showDelete} title="Delete Service" onclose={() => (showDelete = false)}>
	<p class="confirm-text">Are you sure you want to delete service <strong>{deleteTarget?.name}</strong>?</p>
	<div class="modal-actions">
		<button class="btn btn-secondary" onclick={() => (showDelete = false)}>Cancel</button>
		<button class="btn btn-danger" onclick={handleDelete}>Delete</button>
	</div>
</Modal>

<style>
	.status-select { background: var(--color-bg); border: 1px solid var(--color-border); border-radius: 4px; color: var(--color-text); padding: 0.2rem 0.4rem; font-size: 0.8rem; }
</style>
