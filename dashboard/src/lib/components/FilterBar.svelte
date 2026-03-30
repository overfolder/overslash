<script lang="ts">
	import { goto } from '$app/navigation';
	import { page as pageStore } from '$app/stores';
	import type { Identity, ServiceSummary, EventCategory } from '$lib/types';
	import { EVENT_CATEGORY_LABELS } from '$lib/types';

	let {
		identities,
		services,
		filters
	}: {
		identities: Identity[];
		services: ServiceSummary[];
		filters: {
			identity: string;
			category: string;
			service: string;
			since: string;
			until: string;
		};
	} = $props();

	let identity = $state('');
	let category = $state('');
	let service = $state('');
	let since = $state('');
	let until = $state('');

	$effect(() => {
		identity = filters.identity;
		category = filters.category;
		service = filters.service;
		since = filters.since;
		until = filters.until;
	});

	const categories = Object.entries(EVENT_CATEGORY_LABELS) as [EventCategory, string][];

	function applyFilters() {
		const url = new URL($pageStore.url);
		url.searchParams.delete('page');

		if (identity) url.searchParams.set('identity', identity);
		else url.searchParams.delete('identity');

		if (category) url.searchParams.set('category', category);
		else url.searchParams.delete('category');

		if (service) url.searchParams.set('service', service);
		else url.searchParams.delete('service');

		if (since) url.searchParams.set('since', since);
		else url.searchParams.delete('since');

		if (until) url.searchParams.set('until', until);
		else url.searchParams.delete('until');

		goto(url.toString(), { keepFocus: true });
	}

	function clearFilters() {
		identity = '';
		category = '';
		service = '';
		since = '';
		until = '';
		goto('/audit', { keepFocus: true });
	}

	const hasActiveFilters = $derived(
		!!filters.identity || !!filters.category || !!filters.service || !!filters.since || !!filters.until
	);
</script>

<div class="rounded-lg border border-gray-200 bg-white p-4">
	<div class="flex flex-wrap items-end gap-3">
		<!-- Identity -->
		<div class="min-w-[160px] flex-1">
			<label for="filter-identity" class="mb-1 block text-xs font-medium text-gray-500">Identity</label>
			<select
				id="filter-identity"
				bind:value={identity}
				class="w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
			>
				<option value="">All identities</option>
				{#each identities as ident}
					<option value={ident.id}>{ident.name} ({ident.kind})</option>
				{/each}
			</select>
		</div>

		<!-- Event Type -->
		<div class="min-w-[160px] flex-1">
			<label for="filter-category" class="mb-1 block text-xs font-medium text-gray-500">Event Type</label>
			<select
				id="filter-category"
				bind:value={category}
				class="w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
			>
				<option value="">All events</option>
				{#each categories as [key, label]}
					<option value={key}>{label}</option>
				{/each}
			</select>
		</div>

		<!-- Service -->
		<div class="min-w-[140px] flex-1">
			<label for="filter-service" class="mb-1 block text-xs font-medium text-gray-500">Service</label>
			<select
				id="filter-service"
				bind:value={service}
				class="w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
			>
				<option value="">All services</option>
				{#each services as svc}
					<option value={svc.key}>{svc.display_name}</option>
				{/each}
			</select>
		</div>

		<!-- Since -->
		<div class="min-w-[160px] flex-1">
			<label for="filter-since" class="mb-1 block text-xs font-medium text-gray-500">From</label>
			<input
				id="filter-since"
				type="datetime-local"
				bind:value={since}
				class="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
			/>
		</div>

		<!-- Until -->
		<div class="min-w-[160px] flex-1">
			<label for="filter-until" class="mb-1 block text-xs font-medium text-gray-500">To</label>
			<input
				id="filter-until"
				type="datetime-local"
				bind:value={until}
				class="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
			/>
		</div>

		<!-- Buttons -->
		<div class="flex gap-2">
			<button
				onclick={applyFilters}
				class="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:outline-none"
			>
				Apply
			</button>
			{#if hasActiveFilters}
				<button
					onclick={clearFilters}
					class="rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-50"
				>
					Clear
				</button>
			{/if}
		</div>
	</div>
</div>
