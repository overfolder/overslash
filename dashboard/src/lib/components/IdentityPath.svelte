<script lang="ts">
	// Render a SPIFFE-style identity path as muted-slash separated link units.
	// Format: spiffe://<org>/<kind>/<name>/<kind>/<name>/...
	//
	// Each `kind/name` pair is a single clickable link unit (per UI_SPEC §"Audit
	// Log" — Identity column). The forward slashes between units stay muted and
	// non-clickable. The leading `spiffe://` scheme is hidden by default for
	// readability; pass `showScheme` to keep it.
	//
	// Used by the standalone approval page and the approvals list. The audit
	// log no longer uses this component — its rows have only a leaf identity
	// (id + display name) and link directly to /agents/<id>.

	import { parseIdentityPath } from '$lib/identityPath';

	let {
		path,
		pathIds = [],
		showScheme = false
	}: { path: string; pathIds?: string[]; showScheme?: boolean } = $props();

	const segments = $derived(parseIdentityPath(path, pathIds));
</script>

<span class="ip mono">
	{#if showScheme}<span class="scheme">spiffe://</span>{/if}
	{#each segments as seg, i}
		{#if i > 0}<span class="sep">/</span>{/if}
		{#if seg.type === 'org'}
			<a class="unit org" href={seg.href}>{seg.name}</a>
		{:else}
			<a class="unit" href={seg.href}>
				<span class="kind">{seg.kind}</span><span class="sep inner">/</span><span class="name"
					>{seg.name}</span
				>
			</a>
		{/if}
	{/each}
</span>

<style>
	.ip {
		display: inline-flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 0;
		font-size: 0.85rem;
		line-height: 1.4;
	}
	.scheme {
		color: var(--color-text-muted);
		margin-right: 0.1rem;
	}
	.sep {
		color: var(--color-text-muted);
		padding: 0 0.15rem;
		user-select: none;
	}
	.sep.inner {
		padding: 0;
	}
	.unit {
		color: var(--color-text);
		text-decoration: none;
		border-radius: 3px;
		padding: 0 0.1rem;
	}
	.unit:hover {
		color: var(--color-primary);
		text-decoration: underline;
	}
	.unit.org {
		font-weight: 600;
	}
	.kind {
		color: var(--color-text-muted);
	}
	.unit:hover .kind {
		color: var(--color-primary);
	}
</style>
