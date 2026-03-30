<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { RESOURCE_TYPES, ACTIONS, RESOURCE_TYPE_LABELS } from '$lib/types';
	import type { Role, Grant } from '$lib/types';

	let roles = $state<Role[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Map: role_id -> Set of "resource_type:action"
	let grantSets = $state<Record<string, Set<string>>>({});

	onMount(async () => {
		try {
			const allRoles = await api.get<Role[]>('/v1/acl/roles');
			// Load grants for each role
			const detailed = await Promise.all(
				allRoles.map((r) => api.get<Role>(`/v1/acl/roles/${r.id}`))
			);
			roles = detailed;

			const sets: Record<string, Set<string>> = {};
			for (const role of detailed) {
				const s = new Set<string>();
				if (role.grants) {
					for (const g of role.grants) {
						s.add(`${g.resource_type}:${g.action}`);
					}
				}
				sets[role.id] = s;
			}
			grantSets = sets;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to load permissions';
		}
		loading = false;
	});

	function hasGrant(roleId: string, resource: string, action: string): boolean {
		const s = grantSets[roleId];
		if (!s) return false;
		return s.has(`${resource}:${action}`) || s.has(`${resource}:manage`);
	}

	function getActionBadge(
		roleId: string,
		resource: string
	): { label: string; class: string }[] {
		const badges: { label: string; class: string }[] = [];
		const s = grantSets[roleId];
		if (!s) return badges;

		if (s.has(`${resource}:manage`)) {
			return [{ label: 'M', class: 'bg-green-600 text-white' }];
		}
		if (s.has(`${resource}:read`))
			badges.push({ label: 'R', class: 'bg-green-100 text-green-700' });
		if (s.has(`${resource}:write`))
			badges.push({ label: 'W', class: 'bg-blue-100 text-blue-700' });
		if (s.has(`${resource}:delete`))
			badges.push({ label: 'D', class: 'bg-red-100 text-red-700' });
		return badges;
	}
</script>

<div class="space-y-6">
	<h2 class="text-lg font-semibold text-gray-900">Permissions Matrix</h2>
	<p class="text-sm text-gray-500">
		Overview of all roles and their permissions across resource types. <strong>M</strong> = Manage
		(full control), <strong>R</strong> = Read, <strong>W</strong> = Write,
		<strong>D</strong> = Delete.
	</p>

	{#if error}
		<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">{error}</div>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading matrix...</p>
	{:else}
		<div class="bg-white border border-gray-200 rounded-lg overflow-x-auto">
			<table class="w-full text-sm">
				<thead class="bg-gray-50">
					<tr>
						<th class="text-left px-4 py-3 font-medium text-gray-700 sticky left-0 bg-gray-50"
							>Resource</th
						>
						{#each roles as role}
							<th class="text-center px-4 py-3 font-medium text-gray-700 min-w-[120px]">
								<a href="/acl/roles/{role.id}" class="text-blue-600 hover:text-blue-800">
									{role.name}
								</a>
								{#if role.is_builtin}
									<div class="text-xs text-purple-500 font-normal">built-in</div>
								{/if}
							</th>
						{/each}
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-100">
					{#each RESOURCE_TYPES as resource}
						<tr class="hover:bg-gray-50">
							<td
								class="px-4 py-3 font-medium text-gray-900 sticky left-0 bg-white"
							>
								{RESOURCE_TYPE_LABELS[resource] || resource}
							</td>
							{#each roles as role}
								<td class="text-center px-4 py-3">
									<div class="flex justify-center gap-1">
										{#each getActionBadge(role.id, resource) as badge}
											<span
												class="inline-block w-6 h-6 rounded text-xs font-bold leading-6 {badge.class}"
											>
												{badge.label}
											</span>
										{/each}
										{#if getActionBadge(role.id, resource).length === 0}
											<span class="text-gray-300">-</span>
										{/if}
									</div>
								</td>
							{/each}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
