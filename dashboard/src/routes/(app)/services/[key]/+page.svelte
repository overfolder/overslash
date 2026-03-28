<script lang="ts">
	let { data } = $props();

	const actions = $derived(Object.entries(data.service.actions));

	const methodColors: Record<string, string> = {
		GET: 'bg-green-500/10 text-green-400',
		POST: 'bg-blue-500/10 text-blue-400',
		PUT: 'bg-amber-500/10 text-amber-400',
		PATCH: 'bg-amber-500/10 text-amber-400',
		DELETE: 'bg-red-500/10 text-red-400',
	};
</script>

<svelte:head>
	<title>{data.service.display_name} — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div>
		<a href="/services" class="text-sm text-zinc-400 hover:text-white">&larr; Back to services</a>
		<h1 class="mt-2 text-2xl font-bold text-white">{data.service.display_name}</h1>
		<p class="mt-1 text-sm text-zinc-400 font-mono">{data.service.hosts.join(', ')}</p>
	</div>

	<div class="overflow-x-auto rounded-xl border border-zinc-800">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-zinc-800 bg-zinc-900/50">
				<tr>
					<th class="px-4 py-3 font-medium text-zinc-400">Action</th>
					<th class="px-4 py-3 font-medium text-zinc-400">Method</th>
					<th class="px-4 py-3 font-medium text-zinc-400">Path</th>
					<th class="px-4 py-3 font-medium text-zinc-400">Description</th>
					<th class="px-4 py-3 font-medium text-zinc-400">Risk</th>
				</tr>
			</thead>
			<tbody class="divide-y divide-zinc-800">
				{#each actions as [key, action]}
					<tr class="hover:bg-zinc-900/50">
						<td class="px-4 py-3 font-mono text-white text-xs">{key}</td>
						<td class="px-4 py-3">
							<span class="inline-flex rounded px-2 py-0.5 text-xs font-bold {methodColors[action.method] ?? 'bg-zinc-700 text-zinc-300'}">
								{action.method}
							</span>
						</td>
						<td class="px-4 py-3 font-mono text-zinc-400 text-xs">{action.path}</td>
						<td class="px-4 py-3 text-zinc-300">{action.description}</td>
						<td class="px-4 py-3">
							<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium {action.risk === 'write' ? 'bg-amber-500/10 text-amber-400' : 'bg-zinc-700 text-zinc-300'}">
								{action.risk}
							</span>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
</div>
