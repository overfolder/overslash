<script lang="ts">
	import { goto } from '$app/navigation';

	let { data } = $props();
	let expandedId = $state<string | null>(null);

	function applyFilters(action: string, resource_type: string) {
		const params = new URLSearchParams();
		if (action) params.set('action', action);
		if (resource_type) params.set('resource_type', resource_type);
		params.set('limit', data.limit.toString());
		goto(`/audit?${params.toString()}`, { replaceState: true });
	}

	function nextPage() {
		const params = new URLSearchParams();
		if (data.filters.action) params.set('action', data.filters.action);
		if (data.filters.resource_type) params.set('resource_type', data.filters.resource_type);
		params.set('offset', (data.offset + data.limit).toString());
		params.set('limit', data.limit.toString());
		goto(`/audit?${params.toString()}`);
	}

	function prevPage() {
		const params = new URLSearchParams();
		if (data.filters.action) params.set('action', data.filters.action);
		if (data.filters.resource_type) params.set('resource_type', data.filters.resource_type);
		params.set('offset', Math.max(0, data.offset - data.limit).toString());
		params.set('limit', data.limit.toString());
		goto(`/audit?${params.toString()}`);
	}
</script>

<svelte:head>
	<title>Audit Log — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<h1 class="text-2xl font-bold text-white">Audit Log</h1>

	<!-- Filters -->
	<div class="flex gap-3">
		<input
			type="text"
			value={data.filters.action}
			onchange={(e) => applyFilters(e.currentTarget.value, data.filters.resource_type)}
			placeholder="Filter by action..."
			class="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
		/>
		<input
			type="text"
			value={data.filters.resource_type}
			onchange={(e) => applyFilters(data.filters.action, e.currentTarget.value)}
			placeholder="Filter by resource type..."
			class="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
		/>
	</div>

	{#if data.entries.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No audit entries found</p>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Timestamp</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Action</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Resource</th>
						<th class="px-4 py-3 font-medium text-zinc-400">IP</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.entries as entry}
						<tr
							class="hover:bg-zinc-900/50 cursor-pointer"
							onclick={() => expandedId = expandedId === entry.id ? null : entry.id}
						>
							<td class="px-4 py-3 text-zinc-400 text-xs">{new Date(entry.created_at).toLocaleString()}</td>
							<td class="px-4 py-3 font-mono text-white text-xs">{entry.action}</td>
							<td class="px-4 py-3 text-zinc-400 text-xs">{entry.resource_type ?? '—'}</td>
							<td class="px-4 py-3 text-zinc-500 text-xs">{entry.ip_address ?? '—'}</td>
						</tr>
						{#if expandedId === entry.id}
							<tr>
								<td colspan="4" class="bg-zinc-900 px-4 py-3">
									<pre class="overflow-x-auto rounded bg-zinc-800 p-3 text-xs text-zinc-300">{JSON.stringify(entry.detail, null, 2)}</pre>
								</td>
							</tr>
						{/if}
					{/each}
				</tbody>
			</table>
		</div>

		<!-- Pagination -->
		<div class="flex justify-between">
			<button
				class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
				onclick={prevPage}
				disabled={data.offset === 0}
			>
				Previous
			</button>
			<button
				class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
				onclick={nextPage}
				disabled={data.entries.length < data.limit}
			>
				Next
			</button>
		</div>
	{/if}
</div>
