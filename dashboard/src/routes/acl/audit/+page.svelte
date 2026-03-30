<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import type { AuditEntry } from '$lib/types';

	let entries = $state<AuditEntry[]>([]);
	let loading = $state(true);
	let error = $state('');

	onMount(async () => {
		try {
			// Load ACL-related audit entries
			const [roleEntries, assignmentEntries] = await Promise.all([
				api.get<AuditEntry[]>('/v1/audit?resource_type=acl_role&limit=50'),
				api.get<AuditEntry[]>('/v1/audit?resource_type=acl_assignment&limit=50')
			]);
			entries = [...roleEntries, ...assignmentEntries].sort(
				(a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
			);
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Failed to load audit log';
		}
		loading = false;
	});

	function formatAction(action: string): string {
		return action.replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
	}

	function formatDate(dateStr: string): string {
		try {
			return new Date(dateStr).toLocaleString();
		} catch {
			return dateStr;
		}
	}

	function actionColor(action: string): string {
		if (action.includes('created')) return 'bg-green-100 text-green-700';
		if (action.includes('deleted') || action.includes('revoked'))
			return 'bg-red-100 text-red-700';
		if (action.includes('updated')) return 'bg-blue-100 text-blue-700';
		return 'bg-gray-100 text-gray-700';
	}
</script>

<div class="space-y-6">
	<h2 class="text-lg font-semibold text-gray-900">ACL Audit Log</h2>
	<p class="text-sm text-gray-500">Recent changes to roles and role assignments.</p>

	{#if error}
		<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">{error}</div>
	{/if}

	{#if loading}
		<p class="text-gray-500 text-sm">Loading audit log...</p>
	{:else if entries.length === 0}
		<div class="bg-white border border-gray-200 rounded-lg p-8 text-center text-gray-500">
			No ACL changes recorded yet.
		</div>
	{:else}
		<div class="bg-white border border-gray-200 rounded-lg overflow-hidden">
			<table class="w-full text-sm">
				<thead class="bg-gray-50">
					<tr>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Action</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Resource</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">Details</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">By</th>
						<th class="text-left px-4 py-3 font-medium text-gray-700">When</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-100">
					{#each entries as entry}
						<tr class="hover:bg-gray-50">
							<td class="px-4 py-3">
								<span class="text-xs px-2 py-1 rounded-full {actionColor(entry.action)}">
									{formatAction(entry.action)}
								</span>
							</td>
							<td class="px-4 py-3 text-gray-600">
								{entry.resource_type || '-'}
							</td>
							<td class="px-4 py-3">
								<code class="text-xs text-gray-500 bg-gray-50 px-2 py-1 rounded">
									{JSON.stringify(entry.detail)}
								</code>
							</td>
							<td class="px-4 py-3 text-gray-600 font-mono text-xs">
								{entry.identity_id?.substring(0, 8) || 'system'}
							</td>
							<td class="px-4 py-3 text-gray-500 text-xs">
								{formatDate(entry.created_at)}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
