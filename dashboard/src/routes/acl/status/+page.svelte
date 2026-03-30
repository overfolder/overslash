<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { user } from '$lib/stores/auth';
	import type { AclStatus, Identity } from '$lib/types';

	let status = $state<AclStatus | null>(null);
	let identities = $state<Identity[]>([]);
	let loading = $state(true);
	let error = $state('');

	const identityMap = $derived(
		Object.fromEntries(identities.map((i) => [i.id, i]))
	);

	onMount(async () => {
		try {
			[status, identities] = await Promise.all([
				api.get<AclStatus>('/v1/acl/status'),
				api.get<Identity[]>('/v1/identities')
			]);
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to load status';
		}
		loading = false;
	});
</script>

<div class="space-y-6">
	<h2 class="text-lg font-semibold text-gray-900">Admin Status</h2>

	{#if error}
		<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">{error}</div>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading status...</p>
	{:else if status}
		<!-- Warning banner if no admin -->
		{#if !status.has_admin}
			<div class="bg-red-50 border-2 border-red-300 rounded-lg p-6">
				<h3 class="text-red-800 font-bold text-lg">No Org Admin Assigned</h3>
				<p class="text-red-700 mt-2">
					This organization has no admin. Nobody can manage ACL settings, roles, or
					assignments. Contact support or use a direct database intervention to assign an
					org-admin role.
				</p>
			</div>
		{:else}
			<div class="bg-green-50 border border-green-200 rounded-lg p-4">
				<p class="text-green-800 text-sm">
					This organization has <strong>{status.admin_count}</strong> admin{status.admin_count !==
					1
						? 's'
						: ''}.
				</p>
			</div>
		{/if}

		<!-- Admin list -->
		<div class="bg-white border border-gray-200 rounded-lg overflow-hidden">
			<div class="px-4 py-3 bg-gray-50 border-b border-gray-200">
				<h3 class="font-medium text-gray-700">Organization Admins</h3>
			</div>
			{#if status.admin_identities.length === 0}
				<div class="p-6 text-center text-gray-500">No admins found.</div>
			{:else}
				<ul class="divide-y divide-gray-100">
					{#each status.admin_identities as admin}
						{@const identity = identityMap[admin.identity_id]}
						<li class="px-4 py-3 flex items-center justify-between">
							<div>
								<span class="font-medium text-gray-900">
									{identity?.name || 'Unknown'}
								</span>
								<span class="text-gray-500 text-sm ml-2">
									{admin.identity_id.substring(0, 8)}...
								</span>
							</div>
							<div class="flex items-center gap-2">
								{#if admin.identity_id === $user?.identity_id}
									<span
										class="bg-blue-100 text-blue-700 text-xs px-2 py-1 rounded-full"
										>You</span
									>
								{/if}
								<span
									class="bg-green-100 text-green-700 text-xs px-2 py-1 rounded-full"
									>Admin</span
								>
							</div>
						</li>
					{/each}
				</ul>
			{/if}
		</div>

		<!-- All identities for context -->
		<div class="bg-white border border-gray-200 rounded-lg overflow-hidden">
			<div class="px-4 py-3 bg-gray-50 border-b border-gray-200">
				<h3 class="font-medium text-gray-700">All Identities in Org</h3>
			</div>
			<table class="w-full text-sm">
				<thead class="bg-gray-50">
					<tr>
						<th class="text-left px-4 py-2 font-medium text-gray-600">Name</th>
						<th class="text-left px-4 py-2 font-medium text-gray-600">Kind</th>
						<th class="text-left px-4 py-2 font-medium text-gray-600">ID</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-100">
					{#each identities as id}
						<tr class="hover:bg-gray-50">
							<td class="px-4 py-2 text-gray-900">{id.name}</td>
							<td class="px-4 py-2">
								<span
									class="text-xs px-2 py-0.5 rounded-full {id.kind === 'user'
										? 'bg-blue-100 text-blue-700'
										: 'bg-orange-100 text-orange-700'}"
								>
									{id.kind}
								</span>
							</td>
							<td class="px-4 py-2 font-mono text-xs text-gray-500"
								>{id.id.substring(0, 12)}...</td
							>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
