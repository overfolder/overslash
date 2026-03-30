<script lang="ts">
	import { goto } from '$app/navigation';
	import { page as pageStore } from '$app/stores';

	let { page, hasNextPage }: { page: number; hasNextPage: boolean } = $props();

	function navigate(newPage: number) {
		const url = new URL($pageStore.url);
		if (newPage <= 1) {
			url.searchParams.delete('page');
		} else {
			url.searchParams.set('page', String(newPage));
		}
		goto(url.toString(), { keepFocus: true });
	}
</script>

<div class="flex items-center justify-between border-t border-gray-200 bg-white px-4 py-3">
	<div class="text-sm text-gray-500">
		Page {page}
	</div>
	<div class="flex gap-2">
		<button
			onclick={() => navigate(page - 1)}
			disabled={page <= 1}
			class="rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-40"
		>
			Previous
		</button>
		<button
			onclick={() => navigate(page + 1)}
			disabled={!hasNextPage}
			class="rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-40"
		>
			Next
		</button>
	</div>
</div>
