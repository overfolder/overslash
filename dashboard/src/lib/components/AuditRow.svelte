<script lang="ts">
	import type { AuditEntry } from '$lib/types';
	import {
		formatTimestamp,
		getRelativeTime,
		humanizeAction,
		resolveCategory,
		categoryColor,
		kindBadgeColor,
		extractResultSummary
	} from '$lib/utils';
	import Badge from './Badge.svelte';
	import AuditDetail from './AuditDetail.svelte';

	let {
		entry,
		identityMap
	}: {
		entry: AuditEntry;
		identityMap: Record<string, { name: string; kind: string }>;
	} = $props();

	let expanded = $state(false);

	const identity = $derived(
		entry.identity_id ? identityMap[entry.identity_id] : null
	);
	const identityLabel = $derived(identity ? identity.name : 'System');
	const identityKind = $derived(identity ? identity.kind : 'system');
	const category = $derived(resolveCategory(entry.action));
	const categoryLabel = $derived(
		category
			? category.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
			: 'Other'
	);
	const result = $derived(extractResultSummary(entry));
</script>

<tr
	class="cursor-pointer border-b border-gray-100 transition-colors hover:bg-blue-50/50 {expanded ? 'bg-blue-50/30' : ''}"
	onclick={() => (expanded = !expanded)}
>
	<td class="px-4 py-2.5 text-sm whitespace-nowrap">
		<div class="text-gray-900">{formatTimestamp(entry.created_at)}</div>
		<div class="text-xs text-gray-400">{getRelativeTime(entry.created_at)}</div>
	</td>
	<td class="px-4 py-2.5 text-sm">
		<div class="flex items-center gap-1.5">
			<Badge label={identityKind} colorClass={kindBadgeColor(identityKind)} />
			<span class="text-gray-900">{identityLabel}</span>
		</div>
	</td>
	<td class="px-4 py-2.5">
		<Badge label={categoryLabel} colorClass={categoryColor(category)} />
	</td>
	<td class="px-4 py-2.5 text-sm text-gray-600">
		{entry.resource_type ?? '—'}
	</td>
	<td class="px-4 py-2.5 text-sm text-gray-900">
		{humanizeAction(entry.action)}
	</td>
	<td class="px-4 py-2.5 text-sm font-mono text-gray-600">
		{result}
	</td>
	<td class="px-4 py-2.5 text-gray-400">
		<svg
			class="h-4 w-4 transition-transform {expanded ? 'rotate-180' : ''}"
			fill="none"
			stroke="currentColor"
			viewBox="0 0 24 24"
		>
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
		</svg>
	</td>
</tr>
{#if expanded}
	<tr>
		<td colspan="7" class="p-0">
			<AuditDetail {entry} identityName="{identityLabel}{identity ? ` (${identity.kind})` : ''}" />
		</td>
	</tr>
{/if}
