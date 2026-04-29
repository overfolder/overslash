<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import {
		groupsApi,
		identitiesApi,
		servicesApi,
		type Group,
		type GroupGrant,
		type Identity,
		type ServiceInstanceSummary
	} from '$lib/api/groups';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import IdentityPickerModal from '$lib/components/groups/IdentityPickerModal.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';

	const groupId = $derived($page.params.id as string);

	let group = $state<Group | null>(null);
	let grants = $state<GroupGrant[]>([]);
	let memberIds = $state<string[]>([]);
	let identities = $state<Identity[]>([]);
	let services = $state<ServiceInstanceSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	// Edit form
	let editName = $state('');
	let editDescription = $state('');
	let savingMeta = $state(false);
	let metaError = $state<string | null>(null);

	// Add grant form
	let newServiceId = $state('');
	let newAccessLevel = $state('read');
	let newAutoApprove = $state(false);
	let addingGrant = $state(false);
	let grantError = $state<string | null>(null);

	// Modals
	let pickerOpen = $state(false);
	let deleteOpen = $state(false);
	let deleteBusy = $state(false);

	const orgServices = $derived(services.filter((s) => !s.owner_identity_id));
	const identityById = $derived(new Map(identities.map((i) => [i.id, i])));

	const currentUserId = $derived(($page as any).data?.user?.identity_id as string | undefined);
	const isSelfGroup = $derived(group?.system_kind === 'self');
	// Only the Myself owner can manage their own grants — backend cross-owner
	// guard (groups.rs add_grant + remove_grant) rejects everyone else, including
	// org admins. Hide the management UI when an admin opens someone else's
	// Myself via `?include_self=true`; the page becomes read-only audit.
	const isSelfOwner = $derived(
		isSelfGroup && !!currentUserId && group?.owner_identity_id === currentUserId
	);
	// Backend cross-owner guard restricts a Myself group's grants to services
	// owned by its owner. Mirror that in the picker so we never offer choices
	// the API will reject. Only used when the caller is the Myself owner —
	// services list scope is the caller's, so for a non-owner admin this would
	// always be empty anyway, which is why we hide the form entirely above.
	const pickableServices = $derived(
		isSelfGroup
			? services.filter(
					(s) => s.owner_identity_id && s.owner_identity_id === group?.owner_identity_id
				)
			: orgServices
	);

	function selfGroupLabel(g: typeof group): string {
		if (!g) return '';
		if (g.system_kind !== 'self') return g.name;
		const ident = g.owner_identity_id ? identityById.get(g.owner_identity_id) : undefined;
		const email = ident?.email ?? ident?.name;
		return email ? `Myself (${email})` : 'Myself';
	}

	onMount(load);

	async function load() {
		loading = true;
		error = null;
		try {
			const [g, gr, mems, idents, svcs] = await Promise.all([
				groupsApi.get(groupId),
				groupsApi.listGrants(groupId),
				groupsApi.listMembers(groupId),
				identitiesApi.list().catch(() => [] as Identity[]),
				servicesApi.list().catch(() => [] as ServiceInstanceSummary[])
			]);
			group = g;
			grants = gr;
			memberIds = mems;
			identities = idents;
			services = svcs;
			editName = g.name;
			editDescription = g.description;
		} catch (e) {
			error = e instanceof ApiError ? `Error ${e.status}` : 'Failed to load group';
		} finally {
			loading = false;
		}
	}

	function apiErrText(e: unknown): string {
		if (e instanceof ApiError) {
			const body = e.body as { error?: string } | string;
			if (typeof body === 'object' && body && 'error' in body) {
				return body.error ?? `Error ${e.status}`;
			}
			return typeof body === 'string' ? body : `Error ${e.status}`;
		}
		return 'Network error';
	}

	async function saveMeta(e: Event) {
		e.preventDefault();
		if (!group) return;
		savingMeta = true;
		metaError = null;
		try {
			const updated = await groupsApi.update(groupId, {
				name: editName.trim(),
				description: editDescription.trim(),
				allow_raw_http: group.allow_raw_http
			});
			group = updated;
		} catch (e) {
			metaError = apiErrText(e);
		} finally {
			savingMeta = false;
		}
	}

	async function addGrant(e: Event) {
		e.preventDefault();
		if (!newServiceId) {
			grantError = 'Pick a service.';
			return;
		}
		addingGrant = true;
		grantError = null;
		try {
			const g = await groupsApi.addGrant(groupId, {
				service_instance_id: newServiceId,
				access_level: newAccessLevel,
				auto_approve_reads: newAutoApprove
			});
			grants = [...grants, g];
			newServiceId = '';
			newAccessLevel = 'read';
			newAutoApprove = false;
		} catch (e) {
			grantError = apiErrText(e);
		} finally {
			addingGrant = false;
		}
	}

	async function removeGrant(grantId: string) {
		try {
			await groupsApi.removeGrant(groupId, grantId);
			grants = grants.filter((g) => g.id !== grantId);
		} catch (e) {
			grantError = apiErrText(e);
		}
	}

	// Auto-approve toggle: backend has no PATCH, so DELETE + recreate.
	// Tracked in TECH_DEBT.md.
	async function toggleAutoApprove(grant: GroupGrant) {
		try {
			await groupsApi.removeGrant(groupId, grant.id);
			const fresh = await groupsApi.addGrant(groupId, {
				service_instance_id: grant.service_instance_id,
				access_level: grant.access_level,
				auto_approve_reads: !grant.auto_approve_reads
			});
			grants = grants.map((g) => (g.id === grant.id ? fresh : g));
		} catch (e) {
			grantError = apiErrText(e);
			// Reload to recover from partial state.
			load();
		}
	}

	async function pickMember(identity: Identity) {
		pickerOpen = false;
		try {
			await groupsApi.addMember(groupId, identity.id);
			memberIds = [...memberIds, identity.id];
		} catch (e) {
			error = apiErrText(e);
		}
	}

	async function removeMember(id: string) {
		try {
			await groupsApi.removeMember(groupId, id);
			memberIds = memberIds.filter((m) => m !== id);
		} catch (e) {
			error = apiErrText(e);
		}
	}

	async function deleteGroup() {
		deleteBusy = true;
		try {
			await groupsApi.delete(groupId);
			await goto('/org/groups');
		} catch (e) {
			error = apiErrText(e);
			deleteBusy = false;
			deleteOpen = false;
		}
	}
</script>

<div class="page">
	<a class="back" href="/org/groups">← Groups</a>

	{#if loading}
		<div class="state">Loading…</div>
	{:else if error && !group}
		<div class="state error">{error}</div>
	{:else if group}
		<header class="header">
			<h1>{selfGroupLabel(group)}</h1>
			{#if !group.is_system}
				<button class="link-danger" onclick={() => (deleteOpen = true)}>Delete group</button>
			{/if}
		</header>

		{#if error}
			<div class="err" role="alert">
				<span>{error}</span>
				<button type="button" class="dismiss" onclick={() => (error = null)}>Dismiss</button>
			</div>
		{/if}

		{#if !group.is_system}
			<section class="card">
				<h2>Details</h2>
				<form onsubmit={saveMeta} class="form">
					<label>
						<span>Name</span>
						<input type="text" bind:value={editName} required />
					</label>
					<label>
						<span>Description</span>
						<textarea bind:value={editDescription} rows="2"></textarea>
					</label>
					{#if metaError}<div class="err">{metaError}</div>{/if}
					<div class="form-actions">
						<button type="submit" class="btn btn-primary" disabled={savingMeta}>
							{savingMeta ? 'Saving…' : 'Save'}
						</button>
					</div>
				</form>
			</section>
		{/if}

		<section class="card">
			<h2>Service grants</h2>
			<p class="hint">
				{#if isSelfGroup}
					Services this user owns. Myself can only carry grants on its owner's services.
				{:else}
					Permission key patterns that define this group's ceiling. Org-level service instances only.
				{/if}
			</p>

			{#if grants.length === 0}
				<p class="muted">No grants yet.</p>
			{:else}
				<table class="table">
					<thead>
						<tr>
							<th>Service</th>
							<th>Access level</th>
							<th>Auto-approve reads</th>
							{#if !isSelfGroup || isSelfOwner}<th></th>{/if}
						</tr>
					</thead>
					<tbody>
						{#each grants as g (g.id)}
							<tr>
								<td>
									<code>{g.service_name}</code>
								</td>
								<td>{g.access_level}</td>
								<td>
									{#if !isSelfGroup || isSelfOwner}
										<ToggleSwitch
											checked={g.auto_approve_reads}
											onchange={() => toggleAutoApprove(g)}
											label="Auto-approve reads"
										/>
									{:else}
										{g.auto_approve_reads ? 'Yes' : 'No'}
									{/if}
								</td>
								{#if !isSelfGroup || isSelfOwner}
									<td class="row-actions">
										<button class="link-danger" onclick={() => removeGrant(g.id)}>Remove</button>
									</td>
								{/if}
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}

			{#if !isSelfGroup || isSelfOwner}
				<form class="add-grant" onsubmit={addGrant}>
					<select bind:value={newServiceId} required>
						<option value="" disabled>Select service…</option>
						{#each pickableServices as s (s.id)}
							<option value={s.id}>{s.name}</option>
						{/each}
					</select>
					<select bind:value={newAccessLevel}>
						<option value="read">read</option>
						<option value="write">write</option>
						<option value="admin">admin</option>
					</select>
					<span class="inline">
						<ToggleSwitch
							checked={newAutoApprove}
							onchange={(v) => (newAutoApprove = v)}
							labelledby="new-auto-approve-label"
						/>
						<span id="new-auto-approve-label">Auto-approve reads</span>
					</span>
					<button type="submit" class="btn btn-primary" disabled={addingGrant}>
						{addingGrant ? 'Adding…' : 'Add grant'}
					</button>
				</form>
				{#if grantError}<div class="err">{grantError}</div>{/if}
			{/if}
		</section>

		<section class="card">
			<div class="section-head">
				<h2>Members</h2>
				{#if !isSelfGroup}
					<button class="btn btn-primary" onclick={() => (pickerOpen = true)}>Add member</button>
				{/if}
			</div>
			<p class="hint">
				{#if isSelfGroup}
					Myself groups have a fixed membership of one — the owner.
				{:else}
					Only users can be members. Agents inherit access via their owner.
				{/if}
			</p>

			{#if memberIds.length === 0}
				<p class="muted">No members yet.</p>
			{:else}
				<ul class="members">
					{#each memberIds as id (id)}
						{@const ident = identityById.get(id)}
						<li>
							<span class="name">{ident?.name ?? id}</span>
							{#if ident?.external_id}
								<span class="ext">{ident.external_id}</span>
							{/if}
							{#if !isSelfGroup}
								<button class="link-danger" onclick={() => removeMember(id)}>Remove</button>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</section>
	{/if}
</div>

<IdentityPickerModal
	open={pickerOpen}
	{identities}
	excludeIds={memberIds}
	onPick={pickMember}
	onCancel={() => (pickerOpen = false)}
/>

<ConfirmModal
	open={deleteOpen}
	title="Delete group"
	message={`Delete "${group?.name}"? This cannot be undone.`}
	confirmLabel="Delete"
	destructive
	busy={deleteBusy}
	onConfirm={deleteGroup}
	onCancel={() => (deleteOpen = false)}
/>

<style>
	.page {
		max-width: 900px;
		display: flex;
		flex-direction: column;
		gap: var(--space-5);
	}
	.back {
		color: var(--color-text-secondary);
		text-decoration: none;
		font: var(--text-body-sm);
	}
	.back:hover {
		color: var(--color-primary);
	}
	.header {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	h1 {
		margin: 0;
		font: var(--text-h1);
		color: var(--color-text-heading);
	}
	h2 {
		margin: 0 0 var(--space-2);
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: var(--space-5);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.section-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	.hint {
		margin: 0;
		color: var(--color-text-secondary);
		font: var(--text-body-sm);
	}
	.muted {
		margin: 0;
		color: var(--color-text-muted);
		font: var(--text-body-sm);
	}
	.form,
	.add-grant {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-3);
		align-items: center;
	}
	.form {
		flex-direction: column;
		align-items: stretch;
	}
	.form label {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font: var(--text-label);
		color: var(--color-text-secondary);
	}
	.form input,
	.form textarea,
	.add-grant select {
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		font: var(--text-body);
		color: var(--color-text);
		background: var(--color-surface);
	}
	.form-actions {
		display: flex;
		justify-content: flex-end;
	}
	.inline {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		font: var(--text-body-sm);
		color: var(--color-text);
	}
	.table {
		width: 100%;
		border-collapse: collapse;
	}
	.table th,
	.table td {
		padding: var(--space-2) var(--space-3);
		text-align: left;
		font: var(--text-body);
		border-bottom: 1px solid var(--color-border-subtle);
	}
	.table th {
		font: var(--text-label);
		color: var(--color-text-secondary);
	}
	.table code {
		font: var(--text-code);
		color: var(--color-primary);
	}
	.row-actions {
		text-align: right;
	}
	.members {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.members li {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border-subtle);
		border-radius: var(--radius-md);
	}
	.members .name {
		font: var(--text-body-medium);
		color: var(--color-text);
	}
	.members .ext {
		color: var(--color-text-muted);
		font: var(--text-body-sm);
		flex: 1;
	}
	.btn {
		padding: var(--space-2) var(--space-4);
		border-radius: var(--radius-md);
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		cursor: pointer;
		font: var(--text-body-medium);
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	.link-danger {
		background: none;
		border: 0;
		color: var(--color-danger);
		cursor: pointer;
		font: var(--text-body-medium);
	}
	.state {
		padding: var(--space-6);
		color: var(--color-text-secondary);
	}
	.state.error {
		color: var(--color-danger);
	}
	.err {
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-danger);
		border-radius: var(--radius-md);
		background: rgba(230, 56, 54, 0.06);
		color: var(--color-danger);
		font: var(--text-body-sm);
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: var(--space-3);
	}
	.dismiss {
		background: none;
		border: 0;
		color: var(--color-danger);
		font: var(--text-body-sm);
		cursor: pointer;
		text-decoration: underline;
	}
</style>
