<script lang="ts">
	import '$lib/admin.css';
	import { onMount } from 'svelte';
	import { session, formatApiError } from '$lib/session';
	import type {
		GroupResponse, GroupGrantResponse, IdentitySummary, ServiceInstanceSummary
	} from '$lib/types';
	import DataTable from '$lib/components/DataTable.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';

	let groups: GroupResponse[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	// Selected group detail
	let selectedGroup: GroupResponse | null = $state(null);
	let grants: GroupGrantResponse[] = $state([]);
	let memberIds: string[] = $state([]);
	let loadingDetail = $state(false);

	// Org-wide lookups (loaded once)
	let identities: IdentitySummary[] = $state([]);
	let services: ServiceInstanceSummary[] = $state([]);

	// Create group modal
	let showCreate = $state(false);
	let createForm = $state({ name: '', description: '', allow_raw_http: false });
	let createError: string | null = $state(null);
	let saving = $state(false);

	// Edit group modal
	let showEdit = $state(false);
	let editForm = $state({ name: '', description: '', allow_raw_http: false });
	let editError: string | null = $state(null);

	// Delete group
	let showDeleteGroup = $state(false);

	// Add member modal
	let showAddMember = $state(false);
	let addMemberId = $state('');
	let addMemberError: string | null = $state(null);

	// Add grant modal
	let showAddGrant = $state(false);
	let grantForm = $state({ service_instance_id: '', access_level: 'read', auto_approve_reads: false });
	let grantError: string | null = $state(null);

	const groupColumns = [
		{ key: 'name', label: 'Name' },
		{ key: 'description', label: 'Description' },
		{ key: 'allow_raw_http', label: 'Raw HTTP' },
		{ key: '_actions', label: '' }
	];

	const grantColumns = [
		{ key: 'service_name', label: 'Service' },
		{ key: 'access_level', label: 'Access Level' },
		{ key: 'auto_approve_reads', label: 'Auto-Approve Reads' },
		{ key: '_actions', label: '' }
	];

	async function load() {
		loading = true;
		error = null;
		try {
			const [g, ids, svcs] = await Promise.all([
				session.get<GroupResponse[]>('/v1/groups'),
				session.get<IdentitySummary[]>('/v1/identities'),
				session.get<ServiceInstanceSummary[]>('/v1/services')
			]);
			groups = g;
			identities = ids;
			services = svcs;
		} catch (e) {
			error = formatApiError(e);
		} finally {
			loading = false;
		}
	}

	async function selectGroup(g: GroupResponse) {
		selectedGroup = g;
		loadingDetail = true;
		try {
			const [gr, mIds] = await Promise.all([
				session.get<GroupGrantResponse[]>(`/v1/groups/${g.id}/grants`),
				session.get<string[]>(`/v1/groups/${g.id}/members`)
			]);
			grants = gr;
			memberIds = mIds;
		} catch (e) {
			error = formatApiError(e);
		} finally {
			loadingDetail = false;
		}
	}

	function identityName(id: string): string {
		const ident = identities.find((i) => i.id === id);
		return ident ? `${ident.name} (${ident.email ?? ident.kind})` : id.slice(0, 8) + '...';
	}

	let userIdentities = $derived(identities.filter((i) => i.kind === 'user'));
	let orgServices = $derived(services.filter((s) => !s.owner_identity_id));

	// ── Group CRUD ────────────────────────────────────────────────────
	async function handleCreate() {
		createError = null;
		saving = true;
		try {
			await session.post('/v1/groups', createForm);
			showCreate = false;
			createForm = { name: '', description: '', allow_raw_http: false };
			await load();
		} catch (e) {
			createError = formatApiError(e);
		} finally { saving = false; }
	}

	function openEdit() {
		if (!selectedGroup) return;
		editForm = { name: selectedGroup.name, description: selectedGroup.description, allow_raw_http: selectedGroup.allow_raw_http };
		editError = null;
		showEdit = true;
	}

	async function handleEdit() {
		if (!selectedGroup) return;
		editError = null;
		saving = true;
		try {
			await session.put(`/v1/groups/${selectedGroup.id}`, editForm);
			showEdit = false;
			await load();
			// re-select to refresh
			const updated = groups.find((g) => g.id === selectedGroup!.id);
			if (updated) await selectGroup(updated);
		} catch (e) {
			editError = formatApiError(e);
		} finally { saving = false; }
	}

	async function handleDeleteGroup() {
		if (!selectedGroup) return;
		try {
			await session.delete(`/v1/groups/${selectedGroup.id}`);
			showDeleteGroup = false;
			selectedGroup = null;
			grants = [];
			memberIds = [];
			await load();
		} catch (e) {
			error = formatApiError(e);
			showDeleteGroup = false;
		}
	}

	// ── Members ───────────────────────────────────────────────────────
	async function handleAddMember() {
		if (!selectedGroup || !addMemberId) return;
		addMemberError = null;
		try {
			await session.post(`/v1/groups/${selectedGroup.id}/members`, { identity_id: addMemberId });
			showAddMember = false;
			addMemberId = '';
			await selectGroup(selectedGroup);
		} catch (e) {
			addMemberError = formatApiError(e);
		}
	}

	async function removeMember(identityId: string) {
		if (!selectedGroup) return;
		try {
			await session.delete(`/v1/groups/${selectedGroup.id}/members/${identityId}`);
			await selectGroup(selectedGroup);
		} catch (e) {
			error = formatApiError(e);
		}
	}

	// ── Grants ────────────────────────────────────────────────────────
	async function handleAddGrant() {
		if (!selectedGroup) return;
		grantError = null;
		try {
			await session.post(`/v1/groups/${selectedGroup.id}/grants`, {
				service_instance_id: grantForm.service_instance_id,
				access_level: grantForm.access_level,
				auto_approve_reads: grantForm.auto_approve_reads
			});
			showAddGrant = false;
			grantForm = { service_instance_id: '', access_level: 'read', auto_approve_reads: false };
			await selectGroup(selectedGroup);
		} catch (e) {
			grantError = formatApiError(e);
		}
	}

	async function removeGrant(grantId: string) {
		if (!selectedGroup) return;
		try {
			await session.delete(`/v1/groups/${selectedGroup.id}/grants/${grantId}`);
			await selectGroup(selectedGroup);
		} catch (e) {
			error = formatApiError(e);
		}
	}

	onMount(load);
</script>

<svelte:head>
	<title>Groups - Overslash Admin</title>
</svelte:head>

<div class="admin-page">
	<div class="page-header">
		<h1>Groups</h1>
		<button class="btn btn-primary" onclick={() => (showCreate = true)}>Create Group</button>
	</div>

	{#if error}
		<div class="error-msg">{error}</div>
	{/if}

	<div class="card">
		<DataTable items={groups} columns={groupColumns} {loading} emptyMessage="No groups yet.">
			{#snippet cell({ item, column })}
				{#if column.key === 'allow_raw_http'}
					<StatusBadge status={item.allow_raw_http ? 'enabled' : 'disabled'} />
				{:else if column.key === 'name'}
					<button class="link-btn" onclick={() => selectGroup(item as unknown as GroupResponse)}>
						{item.name}
					</button>
				{:else if column.key === '_actions'}
					<div class="row-actions">
						<button class="btn-sm" onclick={() => { selectGroup(item as unknown as GroupResponse).then(() => openEdit()); }}>Edit</button>
						<button class="btn-sm btn-danger" onclick={() => { selectedGroup = item as unknown as GroupResponse; showDeleteGroup = true; }}>Delete</button>
					</div>
				{:else}
					{item[column.key] ?? '—'}
				{/if}
			{/snippet}
		</DataTable>
	</div>

	<!-- Detail panel -->
	{#if selectedGroup}
		<div class="detail-panel">
			<div class="detail-header">
				<h2>{selectedGroup.name}</h2>
				{#if selectedGroup.description}
					<p class="detail-desc">{selectedGroup.description}</p>
				{/if}
			</div>

			{#if loadingDetail}
				<div class="loading-row">
					<div class="spinner"></div> Loading details...
				</div>
			{:else}
				<!-- Members Section -->
				<div class="detail-section">
					<div class="section-header">
						<h3>Members</h3>
						<button class="btn-sm" onclick={() => (showAddMember = true)}>Add Member</button>
					</div>
					{#if memberIds.length === 0}
						<p class="muted">No members assigned.</p>
					{:else}
						<div class="member-list">
							{#each memberIds as mid}
								<div class="member-row">
									<span>{identityName(mid)}</span>
									<button class="btn-sm btn-danger" onclick={() => removeMember(mid)}>Remove</button>
								</div>
							{/each}
						</div>
					{/if}
				</div>

				<!-- Grants Section -->
				<div class="detail-section">
					<div class="section-header">
						<h3>Service Grants</h3>
						<button class="btn-sm" onclick={() => (showAddGrant = true)}>Add Grant</button>
					</div>
					<DataTable items={grants} columns={grantColumns} emptyMessage="No service grants.">
						{#snippet cell({ item, column })}
							{#if column.key === 'access_level'}
								<StatusBadge status={String(item.access_level)} />
							{:else if column.key === 'auto_approve_reads'}
								<StatusBadge status={item.auto_approve_reads ? 'enabled' : 'disabled'} />
							{:else if column.key === '_actions'}
								<button class="btn-sm btn-danger" onclick={() => removeGrant(String(item.id))}>Remove</button>
							{:else}
								{item[column.key] ?? '—'}
							{/if}
						{/snippet}
					</DataTable>
				</div>
			{/if}
		</div>
	{/if}
</div>

<!-- Create Group Modal -->
<Modal open={showCreate} title="Create Group" onclose={() => (showCreate = false)}>
	{#if createError}<div class="modal-error">{createError}</div>{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
		<div class="form-group">
			<label for="grp-name">Name</label>
			<input id="grp-name" type="text" bind:value={createForm.name} required placeholder="engineering" />
		</div>
		<div class="form-group">
			<label for="grp-desc">Description</label>
			<input id="grp-desc" type="text" bind:value={createForm.description} placeholder="Optional description" />
		</div>
		<div class="form-group checkbox-group">
			<label>
				<input type="checkbox" bind:checked={createForm.allow_raw_http} />
				Allow raw HTTP requests
			</label>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showCreate = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={saving}>{saving ? 'Creating...' : 'Create'}</button>
		</div>
	</form>
</Modal>

<!-- Edit Group Modal -->
<Modal open={showEdit} title="Edit Group" onclose={() => (showEdit = false)}>
	{#if editError}<div class="modal-error">{editError}</div>{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleEdit(); }}>
		<div class="form-group">
			<label for="edit-grp-name">Name</label>
			<input id="edit-grp-name" type="text" bind:value={editForm.name} required />
		</div>
		<div class="form-group">
			<label for="edit-grp-desc">Description</label>
			<input id="edit-grp-desc" type="text" bind:value={editForm.description} />
		</div>
		<div class="form-group checkbox-group">
			<label>
				<input type="checkbox" bind:checked={editForm.allow_raw_http} />
				Allow raw HTTP requests
			</label>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showEdit = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
		</div>
	</form>
</Modal>

<!-- Delete Group -->
<Modal open={showDeleteGroup} title="Delete Group" onclose={() => (showDeleteGroup = false)}>
	<p class="confirm-text">Are you sure you want to delete group <strong>{selectedGroup?.name}</strong>? All members and grants will be removed.</p>
	<div class="modal-actions">
		<button class="btn btn-secondary" onclick={() => (showDeleteGroup = false)}>Cancel</button>
		<button class="btn btn-danger" onclick={handleDeleteGroup}>Delete</button>
	</div>
</Modal>

<!-- Add Member Modal -->
<Modal open={showAddMember} title="Add Member" onclose={() => (showAddMember = false)}>
	{#if addMemberError}<div class="modal-error">{addMemberError}</div>{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleAddMember(); }}>
		<div class="form-group">
			<label for="add-member">User</label>
			<select id="add-member" bind:value={addMemberId} required>
				<option value="">Select user...</option>
				{#each userIdentities.filter((u) => !memberIds.includes(u.id)) as user}
					<option value={user.id}>{user.name} ({user.email ?? user.kind})</option>
				{/each}
			</select>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showAddMember = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary">Add</button>
		</div>
	</form>
</Modal>

<!-- Add Grant Modal -->
<Modal open={showAddGrant} title="Add Service Grant" onclose={() => (showAddGrant = false)}>
	{#if grantError}<div class="modal-error">{grantError}</div>{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleAddGrant(); }}>
		<div class="form-group">
			<label for="grant-svc">Service Instance</label>
			<select id="grant-svc" bind:value={grantForm.service_instance_id} required>
				<option value="">Select service...</option>
				{#each orgServices as svc}
					<option value={svc.id}>{svc.name} ({svc.template_key})</option>
				{/each}
			</select>
		</div>
		<div class="form-group">
			<label for="grant-level">Access Level</label>
			<select id="grant-level" bind:value={grantForm.access_level}>
				<option value="read">read</option>
				<option value="write">write</option>
				<option value="admin">admin</option>
			</select>
		</div>
		<div class="form-group checkbox-group">
			<label>
				<input type="checkbox" bind:checked={grantForm.auto_approve_reads} />
				Auto-approve read requests
			</label>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showAddGrant = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary">Add Grant</button>
		</div>
	</form>
</Modal>

<style>
	.link-btn { background: none; border: none; color: var(--color-primary); cursor: pointer; font-size: 0.9rem; padding: 0; text-align: left; }
	.link-btn:hover { color: var(--color-primary-hover); text-decoration: underline; }

	.detail-panel { margin-top: 1.5rem; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 8px; padding: 1.5rem; }
	.detail-header h2 { font-size: 1.2rem; font-weight: 600; margin-bottom: 0.25rem; }
	.detail-desc { color: var(--color-text-muted); font-size: 0.9rem; margin-bottom: 1rem; }

	.detail-section { margin-top: 1.5rem; }
	.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
	.section-header h3 { font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--color-text-muted); }

	.member-list { display: flex; flex-direction: column; gap: 0.5rem; }
	.member-row { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.75rem; background: var(--color-bg); border-radius: 6px; font-size: 0.9rem; }
</style>
