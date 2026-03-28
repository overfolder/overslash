<script lang="ts">
	import { goto } from '$app/navigation';

	let { data } = $props();
	let searchInput = $state(data.query); // eslint-disable-line -- intentionally captures initial value
	let debounceTimer: ReturnType<typeof setTimeout>;

	function onSearch() {
		clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => {
			const params = new URLSearchParams();
			if (searchInput) params.set('q', searchInput);
			goto(`/services?${params.toString()}`, { replaceState: true });
		}, 300);
	}
</script>

<svelte:head>
	<title>Services — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div class="flex items-center justify-between gap-4">
		<h1 class="text-2xl font-bold text-white">Service Registry</h1>
		<input
			type="text"
			bind:value={searchInput}
			oninput={onSearch}
			placeholder="Search services..."
			class="w-64 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
		/>
	</div>

	{#if data.services.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No services found</p>
		</div>
	{:else}
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
			{#each data.services as service}
				<a
					href="/services/{service.key}"
					class="rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-zinc-700"
				>
					<h3 class="font-medium text-white">{service.display_name}</h3>
					<p class="mt-1 text-xs text-zinc-500 font-mono">{service.hosts.join(', ')}</p>
					<p class="mt-3 text-sm text-zinc-400">{service.action_count} actions</p>
				</a>
			{/each}
		</div>
	{/if}
</div>
