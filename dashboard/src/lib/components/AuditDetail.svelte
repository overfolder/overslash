<script lang="ts">
	import type { AuditEntry } from '$lib/types';
	import { formatFullTimestamp } from '$lib/utils';

	let { entry, identityName }: { entry: AuditEntry; identityName: string } = $props();

	let showRaw = $state(false);

	const detailEntries = $derived(
		Object.entries(entry.detail).filter(([, v]) => v !== null && v !== undefined)
	);
</script>

<div class="border-t border-gray-100 bg-gray-50 px-6 py-4">
	<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
		<!-- Metadata -->
		<div>
			<h4 class="mb-2 text-xs font-semibold tracking-wider text-gray-400 uppercase">Metadata</h4>
			<dl class="space-y-1.5 text-sm">
				<div class="flex gap-2">
					<dt class="w-24 shrink-0 font-medium text-gray-500">Entry ID</dt>
					<dd class="font-mono text-xs text-gray-700 break-all">{entry.id}</dd>
				</div>
				<div class="flex gap-2">
					<dt class="w-24 shrink-0 font-medium text-gray-500">Identity</dt>
					<dd class="text-gray-700">{identityName}</dd>
				</div>
				{#if entry.identity_id}
					<div class="flex gap-2">
						<dt class="w-24 shrink-0 font-medium text-gray-500">Identity ID</dt>
						<dd class="font-mono text-xs text-gray-700 break-all">{entry.identity_id}</dd>
					</div>
				{/if}
				{#if entry.resource_id}
					<div class="flex gap-2">
						<dt class="w-24 shrink-0 font-medium text-gray-500">Resource ID</dt>
						<dd class="font-mono text-xs text-gray-700 break-all">{entry.resource_id}</dd>
					</div>
				{/if}
				{#if entry.resource_type}
					<div class="flex gap-2">
						<dt class="w-24 shrink-0 font-medium text-gray-500">Resource</dt>
						<dd class="text-gray-700">{entry.resource_type}</dd>
					</div>
				{/if}
				{#if entry.ip_address}
					<div class="flex gap-2">
						<dt class="w-24 shrink-0 font-medium text-gray-500">IP Address</dt>
						<dd class="font-mono text-xs text-gray-700">{entry.ip_address}</dd>
					</div>
				{/if}
				<div class="flex gap-2">
					<dt class="w-24 shrink-0 font-medium text-gray-500">Timestamp</dt>
					<dd class="text-gray-700">{formatFullTimestamp(entry.created_at)}</dd>
				</div>
			</dl>
		</div>

		<!-- Detail -->
		<div>
			<div class="mb-2 flex items-center justify-between">
				<h4 class="text-xs font-semibold tracking-wider text-gray-400 uppercase">Detail</h4>
				<button
					onclick={() => (showRaw = !showRaw)}
					class="text-xs text-blue-600 hover:text-blue-800"
				>
					{showRaw ? 'Formatted' : 'Raw JSON'}
				</button>
			</div>

			{#if showRaw}
				<pre class="max-h-64 overflow-auto rounded-md bg-gray-800 p-3 font-mono text-xs text-green-300">{JSON.stringify(entry.detail, null, 2)}</pre>
			{:else if detailEntries.length === 0}
				<p class="text-sm text-gray-400 italic">No additional details</p>
			{:else}
				<dl class="space-y-1.5 text-sm">
					{#each detailEntries as [key, value]}
						<div class="flex gap-2">
							<dt class="w-28 shrink-0 font-medium text-gray-500">{key}</dt>
							<dd class="text-gray-700 break-all">
								{#if typeof value === 'object'}
									<span class="font-mono text-xs">{JSON.stringify(value)}</span>
								{:else}
									{value}
								{/if}
							</dd>
						</div>
					{/each}
				</dl>
			{/if}
		</div>
	</div>
</div>
