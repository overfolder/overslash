<script lang="ts">
	import { page } from '$app/stores';

	let { data, children } = $props();

	const navGroups = [
		{
			label: 'Manage',
			items: [
				{ href: '/identities', label: 'Identities' },
				{ href: '/api-keys', label: 'API Keys' },
			],
		},
		{
			label: 'Security',
			items: [
				{ href: '/secrets', label: 'Secrets' },
				{ href: '/permissions', label: 'Permissions' },
				{ href: '/approvals', label: 'Approvals' },
			],
		},
		{
			label: 'Integrations',
			items: [
				{ href: '/connections', label: 'Connections' },
				{ href: '/services', label: 'Services' },
				{ href: '/byoc-credentials', label: 'BYOC Credentials' },
			],
		},
		{
			label: 'Observe',
			items: [
				{ href: '/audit', label: 'Audit Log' },
			],
		},
	];

	let sidebarOpen = $state(false);
</script>

<div class="flex h-screen bg-zinc-950 text-zinc-100">
	<!-- Sidebar -->
	<aside
		class="fixed inset-y-0 left-0 z-40 w-60 transform border-r border-zinc-800 bg-zinc-900 transition-transform lg:static lg:translate-x-0 {sidebarOpen ? 'translate-x-0' : '-translate-x-full'}"
	>
		<div class="flex h-14 items-center border-b border-zinc-800 px-4">
			<a href="/" class="text-lg font-bold text-white">Overslash</a>
		</div>

		<nav class="space-y-4 p-4">
			{#each navGroups as group}
				<div>
					<h3 class="mb-1 px-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
						{group.label}
					</h3>
					{#each group.items as item}
						<a
							href={item.href}
							class="block rounded-md px-2 py-1.5 text-sm transition-colors {$page.url.pathname.startsWith(item.href) ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200'}"
						>
							{item.label}
						</a>
					{/each}
				</div>
			{/each}
		</nav>
	</aside>

	<!-- Mobile overlay -->
	{#if sidebarOpen}
		<button
			class="fixed inset-0 z-30 bg-black/50 lg:hidden"
			onclick={() => (sidebarOpen = false)}
			aria-label="Close sidebar"
		></button>
	{/if}

	<!-- Main content -->
	<div class="flex flex-1 flex-col overflow-hidden">
		<!-- Header -->
		<header class="flex h-14 items-center justify-between border-b border-zinc-800 px-4">
			<button
				class="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-800 lg:hidden"
				onclick={() => (sidebarOpen = !sidebarOpen)}
				aria-label="Toggle sidebar"
			>
				<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
				</svg>
			</button>

			<div class="flex items-center gap-3 ml-auto">
				<span class="text-sm text-zinc-400">{data.user.email}</span>
				<form method="POST" action="/logout">
					<button
						type="submit"
						class="rounded-md px-3 py-1.5 text-sm text-zinc-400 hover:bg-zinc-800 hover:text-white transition-colors"
					>
						Logout
					</button>
				</form>
			</div>
		</header>

		<!-- Page content -->
		<main class="flex-1 overflow-y-auto p-6">
			{@render children()}
		</main>
	</div>
</div>
