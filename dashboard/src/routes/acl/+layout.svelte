<script lang="ts">
	import { page } from '$app/stores';
	import { permissions } from '$lib/stores/auth';

	const tabs = [
		{ href: '/acl/roles', label: 'Roles' },
		{ href: '/acl/assignments', label: 'Assignments' },
		{ href: '/acl/matrix', label: 'Permissions Matrix' },
		{ href: '/acl/audit', label: 'Audit Log' },
		{ href: '/acl/status', label: 'Admin Status' }
	];
</script>

<div>
	<h1 class="text-2xl font-bold text-gray-900 mb-6">Access Control</h1>

	{#if !$permissions?.is_admin}
		<div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
			<p class="text-yellow-800 text-sm">
				You have read-only access to ACL settings. Contact an org admin to make changes.
			</p>
		</div>
	{/if}

	<div class="border-b border-gray-200 mb-6">
		<nav class="flex space-x-8">
			{#each tabs as tab}
				<a
					href={tab.href}
					class="pb-3 px-1 text-sm font-medium border-b-2 transition-colors {$page.url.pathname.startsWith(
						tab.href
					)
						? 'border-blue-600 text-blue-600'
						: 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}"
				>
					{tab.label}
				</a>
			{/each}
		</nav>
	</div>

	<slot />
</div>
