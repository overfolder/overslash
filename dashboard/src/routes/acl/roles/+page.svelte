<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { permissions } from '$lib/stores/auth';
	import type { Role } from '$lib/types';

	let roles = $state<Role[]>([]);
	let loading = $state(true);
	let error = $state('');
	let showCreate = $state(false);
	let newName = $state('');
	let newSlug = $state('');
	let newDescription = $state('');
	let creating = $state(false);

	const isAdmin = $derived($permissions?.is_admin ?? false);

	onMount(loadRoles);

	async function loadRoles() {
		try {
			roles = await api.get<Role[]>('/v1/acl/roles');
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to load roles';
		}
		loading = false;
	}

	async function createRole() {
		if (!newName.trim() || !newSlug.trim()) return;
		creating = true;
		error = '';
		try {
			await api.post('/v1/acl/roles', {
				name: newName,
				slug: newSlug,
				description: newDescription
			});
			showCreate = false;
			newName = '';
			newSlug = '';
			newDescription = '';
			await loadRoles();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to create role';
		}
		creating = false;
	}

	async function deleteRole(id: string) {
		if (!confirm('Delete this role? All assignments will be removed.')) return;
		try {
			await api.del(`/v1/acl/roles/${id}`);
			await loadRoles();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to delete role';
		}
	}

	function autoSlug() {
		newSlug = newName
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-|-$/g, '');
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h2 class="text-lg font-semibold text-gray-900">Roles</h2>
		{#if isAdmin}
			<button
				onclick={() => (showCreate = !showCreate)}
				class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-blue-700 transition-colors"
			>
				{showCreate ? 'Cancel' : 'Create Role'}
			</button>
		{/if}
	</div>

	{#if error}
		<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">{error}</div>
	{/if}

	{#if showCreate}
		<div class="bg-white border border-gray-200 rounded-lg p-4 space-y-4">
			<h3 class="font-medium text-gray-900">New Role</h3>
			<div class="grid grid-cols-2 gap-4">
				<div>
					<label for="role-name" class="block text-sm font-medium text-gray-700 mb-1"
						>Name</label
					>
					<input
						id="role-name"
						bind:value={newName}
						oninput={autoSlug}
						class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
						placeholder="e.g. Developer"
					/>
				</div>
				<div>
					<label for="role-slug" class="block text-sm font-medium text-gray-700 mb-1"
						>Slug</label
					>
					<input
						id="role-slug"
						bind:value={newSlug}
						class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
						placeholder="e.g. developer"
					/>
				</div>
			</div>
			<div>
				<label for="role-desc" class="block text-sm font-medium text-gray-700 mb-1"
					>Description</label
				>
				<input
					id="role-desc"
					bind:value={newDescription}
					class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
					placeholder="What can this role do?"
				/>
			</div>
			<button
				onclick={createRole}
				disabled={creating || !newName.trim() || !newSlug.trim()}
				class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50 transition-colors"
			>
				{creating ? 'Creating...' : 'Create'}
			</button>
		</div>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading roles...</p>
	{:else}
		<div class="bg-white border border-gray-200 rounded-lg overflow-hidden">
			<table class="w-full text-sm">
				<thead class="bg-gray-50">
					<tr>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Name</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Slug</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Description</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Type</th>
						{#if isAdmin}
							<th class="text-right px-4 py-3 font-medium text-gray-700">Actions</th>
						{/if}
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-100">
					{#each roles as role}
						<tr class="hover:bg-gray-50">
							<td class="px-4 py-3">
								<a
									href="/acl/roles/{role.id}"
									class="text-blue-600 hover:text-blue-800 font-medium"
								>
									{role.name}
								</a>
							</td>
							<td class="px-4 py-3 text-gray-600 font-mono text-xs">{role.slug}</td>
							<td class="px-4 py-3 text-gray-600">{role.description}</td>
							<td class="px-4 py-3">
								{#if role.is_builtin}
									<span
										class="bg-purple-100 text-purple-700 text-xs px-2 py-1 rounded-full font-medium"
										>Built-in</span
									>
								{:else}
									<span
										class="bg-gray-100 text-gray-600 text-xs px-2 py-1 rounded-full font-medium"
										>Custom</span
									>
								{/if}
							</td>
							{#if isAdmin}
								<td class="px-4 py-3 text-right">
									{#if !role.is_builtin}
										<button
											onclick={() => deleteRole(role.id)}
											class="text-red-600 hover:text-red-800 text-xs"
										>
											Delete
										</button>
									{:else}
										<span class="text-gray-400 text-xs">-</span>
									{/if}
								</td>
							{/if}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
