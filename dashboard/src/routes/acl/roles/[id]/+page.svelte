<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { permissions } from '$lib/stores/auth';
	import { RESOURCE_TYPES, ACTIONS, RESOURCE_TYPE_LABELS } from '$lib/types';
	import type { Role, Grant } from '$lib/types';

	const roleId = $derived($page.params.id);
	let role = $state<Role | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let error = $state('');
	let success = $state('');

	// Permission matrix state: resource_type -> Set of actions
	let grantMatrix = $state<Record<string, Set<string>>>({});

	const isAdmin = $derived($permissions?.is_admin ?? false);
	const canEdit = $derived(isAdmin && !role?.is_builtin);

	onMount(loadRole);

	async function loadRole() {
		try {
			role = await api.get<Role>(`/v1/acl/roles/${roleId}`);
			// Build matrix from grants
			const matrix: Record<string, Set<string>> = {};
			for (const rt of RESOURCE_TYPES) {
				matrix[rt] = new Set();
			}
			if (role.grants) {
				for (const g of role.grants) {
					if (matrix[g.resource_type]) {
						matrix[g.resource_type].add(g.action);
					}
				}
			}
			grantMatrix = matrix;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to load role';
		}
		loading = false;
	}

	function toggleGrant(resource: string, action: string) {
		if (!canEdit) return;
		const current = grantMatrix[resource];
		if (current.has(action)) {
			current.delete(action);
		} else {
			current.add(action);
		}
		grantMatrix = { ...grantMatrix, [resource]: new Set(current) };
	}

	async function saveGrants() {
		saving = true;
		error = '';
		success = '';
		try {
			const grants: { resource_type: string; action: string }[] = [];
			for (const [resource, actions] of Object.entries(grantMatrix)) {
				for (const action of actions) {
					grants.push({ resource_type: resource, action });
				}
			}
			await api.put(`/v1/acl/roles/${roleId}/grants`, { grants });
			success = 'Permissions saved successfully';
			setTimeout(() => (success = ''), 3000);
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to save permissions';
		}
		saving = false;
	}

	// Editing name/description
	let editName = $state('');
	let editDescription = $state('');
	let editingMeta = $state(false);

	function startEditMeta() {
		if (!role || !canEdit) return;
		editName = role.name;
		editDescription = role.description;
		editingMeta = true;
	}

	async function saveMeta() {
		if (!role) return;
		try {
			const updated = await api.put<Role>(`/v1/acl/roles/${roleId}`, {
				name: editName,
				description: editDescription
			});
			role = { ...role, name: updated.name, description: updated.description };
			editingMeta = false;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to update role';
		}
	}
</script>

{#if loading}
	<p class="text-gray-500">Loading role...</p>
{:else if role}
	<div class="space-y-6">
		<div class="flex items-center justify-between">
			<div>
				<a href="/acl/roles" class="text-sm text-blue-600 hover:text-blue-800"
					>&larr; Back to Roles</a
				>
			</div>
		</div>

		<!-- Role info -->
		<div class="bg-white border border-gray-200 rounded-lg p-6">
			{#if editingMeta}
				<div class="space-y-3">
					<input
						bind:value={editName}
						class="w-full border border-gray-300 rounded-lg px-3 py-2 text-lg font-bold"
					/>
					<input
						bind:value={editDescription}
						class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
					/>
					<div class="flex gap-2">
						<button
							onclick={saveMeta}
							class="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
							>Save</button
						>
						<button
							onclick={() => (editingMeta = false)}
							class="bg-gray-200 text-gray-700 px-3 py-1 rounded text-sm hover:bg-gray-300"
							>Cancel</button
						>
					</div>
				</div>
			{:else}
				<div class="flex items-start justify-between">
					<div>
						<h2 class="text-xl font-bold text-gray-900">{role.name}</h2>
						<p class="text-sm text-gray-500 mt-1">{role.description}</p>
						<div class="flex gap-2 mt-2">
							<span class="text-xs font-mono text-gray-400">{role.slug}</span>
							{#if role.is_builtin}
								<span
									class="bg-purple-100 text-purple-700 text-xs px-2 py-0.5 rounded-full"
									>Built-in</span
								>
							{/if}
						</div>
					</div>
					{#if canEdit}
						<button
							onclick={startEditMeta}
							class="text-sm text-blue-600 hover:text-blue-800"
						>
							Edit
						</button>
					{/if}
				</div>
			{/if}
		</div>

		{#if error}
			<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">
				{error}
			</div>
		{/if}
		{#if success}
			<div class="bg-green-50 border border-green-200 rounded-lg p-3 text-green-700 text-sm">
				{success}
			</div>
		{/if}

		<!-- Permission matrix -->
		<div class="bg-white border border-gray-200 rounded-lg overflow-hidden">
			<div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
				<h3 class="font-semibold text-gray-900">Permissions</h3>
				{#if canEdit}
					<button
						onclick={saveGrants}
						disabled={saving}
						class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50"
					>
						{saving ? 'Saving...' : 'Save Permissions'}
					</button>
				{/if}
			</div>
			<table class="w-full text-sm">
				<thead class="bg-gray-50">
					<tr>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Resource</th>
						{#each ACTIONS as action}
							<th class="text-center px-4 py-3 font-medium text-gray-700 capitalize"
								>{action}</th
							>
						{/each}
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-100">
					{#each RESOURCE_TYPES as resource}
						<tr class="hover:bg-gray-50">
							<td class="px-4 py-3 font-medium text-gray-900">
								{RESOURCE_TYPE_LABELS[resource] || resource}
							</td>
							{#each ACTIONS as action}
								<td class="text-center px-4 py-3">
									<input
										type="checkbox"
										checked={grantMatrix[resource]?.has(action) ?? false}
										disabled={!canEdit}
										onchange={() => toggleGrant(resource, action)}
										class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 disabled:opacity-50"
									/>
								</td>
							{/each}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</div>
{:else}
	<p class="text-red-600">Role not found</p>
{/if}
