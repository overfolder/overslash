<script lang="ts">
	import '../app.css';
	import { page } from '$app/stores';
	import { user, permissions } from '$lib/stores/auth';
	import { api } from '$lib/api';
	import { onMount } from 'svelte';
	import type { UserInfo, MyPermissions } from '$lib/types';

	let loading = $state(true);

	onMount(async () => {
		try {
			const me = await api.get<UserInfo>('/auth/me');
			user.set(me);
			const perms = await api.get<MyPermissions>('/v1/acl/me');
			permissions.set(perms);
		} catch {
			// Not authenticated — redirect to login
			if (!$page.url.pathname.startsWith('/login')) {
				window.location.href = '/login';
				return;
			}
		}
		loading = false;
	});

	function hasPermission(resource: string, action: string): boolean {
		const p = $permissions;
		if (!p) return false;
		if (p.is_admin) return true;
		return p.permissions.some(
			(perm) =>
				perm.resource_type === resource &&
				(perm.action === action || perm.action === 'manage')
		);
	}

	const navItems = [
		{ href: '/acl/roles', label: 'Roles', resource: 'acl' },
		{ href: '/acl/assignments', label: 'Assignments', resource: 'acl' },
		{ href: '/acl/matrix', label: 'Permissions Matrix', resource: 'acl' },
		{ href: '/acl/audit', label: 'ACL Audit', resource: 'acl' },
		{ href: '/acl/status', label: 'Admin Status', resource: 'acl' }
	];
</script>

{#if loading}
	<div class="flex items-center justify-center min-h-screen bg-gray-50">
		<div class="text-gray-500">Loading...</div>
	</div>
{:else if $page.url.pathname.startsWith('/login')}
	<slot />
{:else}
	<div class="flex min-h-screen bg-gray-50">
		<!-- Sidebar -->
		<aside class="w-64 bg-gray-900 text-white flex flex-col">
			<div class="p-4 border-b border-gray-700">
				<h1 class="text-lg font-bold">Overslash</h1>
				<p class="text-xs text-gray-400 mt-1">{$user?.email}</p>
			</div>
			<nav class="flex-1 p-4 space-y-1">
				{#each navItems as item}
					{@const allowed = hasPermission(item.resource, 'read')}
					<a
						href={allowed ? item.href : '#'}
						class="block px-3 py-2 rounded text-sm transition-colors {$page.url.pathname.startsWith(item.href)
							? 'bg-gray-700 text-white'
							: allowed
								? 'text-gray-300 hover:bg-gray-800 hover:text-white'
								: 'text-gray-600 cursor-not-allowed'}"
					>
						{item.label}
						{#if !allowed}
							<span class="text-xs ml-1">(restricted)</span>
						{/if}
					</a>
				{/each}
			</nav>
			<div class="p-4 border-t border-gray-700">
				{#if $permissions?.is_admin}
					<span class="text-xs bg-green-600 text-white px-2 py-1 rounded">Org Admin</span>
				{:else}
					<span class="text-xs bg-gray-600 text-white px-2 py-1 rounded">Member</span>
				{/if}
			</div>
		</aside>

		<!-- Main content -->
		<main class="flex-1 p-8">
			<slot />
		</main>
	</div>
{/if}
