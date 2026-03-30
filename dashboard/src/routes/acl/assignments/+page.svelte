<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { permissions } from '$lib/stores/auth';
	import type { Assignment, Identity, Role } from '$lib/types';

	let assignments = $state<Assignment[]>([]);
	let identities = $state<Identity[]>([]);
	let roles = $state<Role[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Assign form
	let showAssign = $state(false);
	let selectedIdentity = $state('');
	let selectedRole = $state('');
	let assigning = $state(false);

	const isAdmin = $derived($permissions?.is_admin ?? false);

	// Lookup maps
	const identityMap = $derived(
		Object.fromEntries(identities.map((i) => [i.id, i]))
	);
	const roleMap = $derived(Object.fromEntries(roles.map((r) => [r.id, r])));

	// Group assignments by identity
	const assignmentsByIdentity = $derived(() => {
		const map = new Map<string, Assignment[]>();
		for (const a of assignments) {
			const existing = map.get(a.identity_id) || [];
			existing.push(a);
			map.set(a.identity_id, existing);
		}
		return map;
	});

	onMount(loadAll);

	async function loadAll() {
		try {
			[assignments, identities, roles] = await Promise.all([
				api.get<Assignment[]>('/v1/acl/assignments'),
				api.get<Identity[]>('/v1/identities'),
				api.get<Role[]>('/v1/acl/roles')
			]);
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to load data';
		}
		loading = false;
	}

	async function assignRole() {
		if (!selectedIdentity || !selectedRole) return;
		assigning = true;
		error = '';
		try {
			await api.post('/v1/acl/assignments', {
				identity_id: selectedIdentity,
				role_id: selectedRole
			});
			showAssign = false;
			selectedIdentity = '';
			selectedRole = '';
			await loadAll();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to assign role';
		}
		assigning = false;
	}

	async function revokeAssignment(id: string) {
		if (!confirm('Revoke this role assignment?')) return;
		try {
			await api.del(`/v1/acl/assignments/${id}`);
			await loadAll();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to revoke assignment';
		}
	}

	function getIdentityAssignments(identityId: string): Assignment[] {
		return assignments.filter((a) => a.identity_id === identityId);
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h2 class="text-lg font-semibold text-gray-900">Role Assignments</h2>
		{#if isAdmin}
			<button
				onclick={() => (showAssign = !showAssign)}
				class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-blue-700 transition-colors"
			>
				{showAssign ? 'Cancel' : 'Assign Role'}
			</button>
		{/if}
	</div>

	{#if error}
		<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">{error}</div>
	{/if}

	{#if showAssign}
		<div class="bg-white border border-gray-200 rounded-lg p-4 space-y-4">
			<h3 class="font-medium text-gray-900">Assign Role to User</h3>
			<div class="grid grid-cols-2 gap-4">
				<div>
					<label for="assign-identity" class="block text-sm font-medium text-gray-700 mb-1"
						>User</label
					>
					<select
						id="assign-identity"
						bind:value={selectedIdentity}
						class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
					>
						<option value="">Select a user...</option>
						{#each identities.filter((i) => i.kind === 'user') as identity}
							<option value={identity.id}>{identity.name}</option>
						{/each}
					</select>
				</div>
				<div>
					<label for="assign-role" class="block text-sm font-medium text-gray-700 mb-1"
						>Role</label
					>
					<select
						id="assign-role"
						bind:value={selectedRole}
						class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
					>
						<option value="">Select a role...</option>
						{#each roles as role}
							<option value={role.id}>{role.name}</option>
						{/each}
					</select>
				</div>
			</div>
			<button
				onclick={assignRole}
				disabled={assigning || !selectedIdentity || !selectedRole}
				class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50 transition-colors"
			>
				{assigning ? 'Assigning...' : 'Assign'}
			</button>
		</div>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading assignments...</p>
	{:else}
		<div class="bg-white border border-gray-200 rounded-lg overflow-hidden">
			<table class="w-full text-sm">
				<thead class="bg-gray-50">
					<tr>
						<th class="text-left px-4 py-3 font-medium text-gray-700">User</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Kind</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Assigned Roles</th>
						{#if isAdmin}
							<th class="text-right px-4 py-3 font-medium text-gray-700">Actions</th>
						{/if}
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-100">
					{#each identities as identity}
						{@const userAssignments = getIdentityAssignments(identity.id)}
						<tr class="hover:bg-gray-50">
							<td class="px-4 py-3">
								<div class="font-medium text-gray-900">{identity.name}</div>
							</td>
							<td class="px-4 py-3">
								<span
									class="text-xs px-2 py-0.5 rounded-full {identity.kind === 'user'
										? 'bg-blue-100 text-blue-700'
										: 'bg-orange-100 text-orange-700'}"
								>
									{identity.kind}
								</span>
							</td>
							<td class="px-4 py-3">
								<div class="flex flex-wrap gap-1">
									{#each userAssignments as assignment}
										{@const role = roleMap[assignment.role_id]}
										{#if role}
											<span
												class="inline-flex items-center gap-1 text-xs px-2 py-1 rounded-full {role.slug ===
												'org-admin'
													? 'bg-green-100 text-green-700'
													: 'bg-gray-100 text-gray-700'}"
											>
												{role.name}
												{#if isAdmin}
													<button
														onclick={() => revokeAssignment(assignment.id)}
														class="text-red-500 hover:text-red-700 ml-1"
														title="Revoke"
													>
														&times;
													</button>
												{/if}
											</span>
										{/if}
									{/each}
									{#if userAssignments.length === 0}
										<span class="text-gray-400 text-xs">No roles assigned</span>
									{/if}
								</div>
							</td>
							{#if isAdmin}
								<td class="px-4 py-3 text-right">
									<button
										onclick={() => {
											selectedIdentity = identity.id;
											showAssign = true;
										}}
										class="text-blue-600 hover:text-blue-800 text-xs"
									>
										Assign
									</button>
								</td>
							{/if}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
