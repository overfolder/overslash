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

	let {
		path,
		pathIds = [],
		showScheme = false
	}: { path: string; pathIds?: string[]; showScheme?: boolean } = $props();

	type Segment =
		| { type: 'org'; name: string; href: string }
		| { type: 'unit'; kind: string; name: string; href: string };

	function parse(p: string, ids: string[]): Segment[] {
		const stripped = p.replace(/^spiffe:\/\//, '');
		const parts = stripped.split('/').filter(Boolean);
		if (parts.length === 0) return [];
		const out: Segment[] = [];
		// First part is the org slug.
		out.push({ type: 'org', name: parts[0], href: `/org` });
		// Remaining parts come in (kind, name) pairs aligned with `ids`
		// (one id per pair, no id for the org slug).
		let unitIndex = 0;
		for (let i = 1; i + 1 < parts.length; i += 2) {
			const kind = parts[i];
			const name = parts[i + 1];
			const id = ids[unitIndex];
			// Agent units link by id when available so /agents/<id> can
			// resolve directly without a name → id lookup. User units stay
			// name-keyed to match the /users/[name] route. If the caller
			// hasn't supplied ids (legacy), fall back to name-keyed agent
			// links and accept the (rare) name-collision risk.
			const href =
				kind === 'user'
					? `/users/${name}`
					: id
						? `/agents/${id}`
						: `/agents/${name}`;
			out.push({ type: 'unit', kind, name, href });
			unitIndex += 1;
		}
		return out;
	}

	const segments = $derived(parse(path, pathIds));
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
