<script lang="ts">
	import type { AuditEntry } from '$lib/types';
	import AuditRow from './AuditRow.svelte';

	let {
		entries,
		identityMap
	}: {
		entries: AuditEntry[];
		identityMap: Record<string, { name: string; kind: string }>;
	} = $props();
</script>

<div class="overflow-x-auto rounded-lg border border-gray-200 bg-white">
	<table class="w-full min-w-[800px] text-left">
		<thead>
			<tr class="border-b border-gray-200 bg-gray-50">
				<th class="px-4 py-2.5 text-xs font-semibold tracking-wider text-gray-500 uppercase">Time</th>
				<th class="px-4 py-2.5 text-xs font-semibold tracking-wider text-gray-500 uppercase">Identity</th>
				<th class="px-4 py-2.5 text-xs font-semibold tracking-wider text-gray-500 uppercase">Event Type</th>
				<th class="px-4 py-2.5 text-xs font-semibold tracking-wider text-gray-500 uppercase">Service</th>
				<th class="px-4 py-2.5 text-xs font-semibold tracking-wider text-gray-500 uppercase">Action</th>
				<th class="px-4 py-2.5 text-xs font-semibold tracking-wider text-gray-500 uppercase">Result</th>
				<th class="w-10 px-4 py-2.5"></th>
			</tr>
		</thead>
		<tbody>
			{#if entries.length === 0}
				<tr>
					<td colspan="7" class="px-4 py-12 text-center text-sm text-gray-400">
						No audit entries found. Try adjusting your filters.
					</td>
				</tr>
			{:else}
				{#each entries as entry (entry.id)}
					<AuditRow {entry} {identityMap} />
				{/each}
			{/if}
		</tbody>
	</table>
</div>
