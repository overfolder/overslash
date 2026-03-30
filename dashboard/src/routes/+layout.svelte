<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Overslash Dashboard</title>
</svelte:head>

<div class="flex h-screen bg-gray-50">
	<!-- Sidebar -->
	<aside class="flex w-56 flex-col border-r border-gray-200 bg-gray-900 text-white">
		<div class="flex h-14 items-center border-b border-gray-700 px-5">
			<span class="text-lg font-semibold tracking-tight">Overslash</span>
		</div>
		<nav class="flex-1 px-3 py-4">
			<a
				href="/audit"
				class="flex items-center gap-2 rounded-md bg-gray-800 px-3 py-2 text-sm font-medium text-white"
			>
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
				</svg>
				Audit Log
			</a>
		</nav>
		<div class="border-t border-gray-700 px-5 py-3 text-xs text-gray-400">
			Dashboard v0.1
		</div>
	</aside>

	<!-- Main content -->
	<main class="flex-1 overflow-auto">
		{@render children()}
	</main>
</div>
