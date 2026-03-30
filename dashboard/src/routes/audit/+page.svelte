<script lang="ts">
	import FilterBar from '$lib/components/FilterBar.svelte';
	import AuditTable from '$lib/components/AuditTable.svelte';
	import Pagination from '$lib/components/Pagination.svelte';

	let { data } = $props();
</script>

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="border-b border-gray-200 bg-white px-6 py-4">
		<h1 class="text-xl font-semibold text-gray-900">Audit Log</h1>
		<p class="mt-1 text-sm text-gray-500">
			View and filter all activity across your organization.
		</p>
	</div>

	<!-- Content -->
	<div class="flex-1 space-y-4 overflow-auto p-6">
		<FilterBar
			identities={data.identities}
			services={data.services}
			filters={data.filters}
		/>

		<AuditTable
			entries={data.entries}
			identityMap={data.identityMap}
		/>

		<Pagination
			page={data.page}
			hasNextPage={data.hasNextPage}
		/>
	</div>
</div>
