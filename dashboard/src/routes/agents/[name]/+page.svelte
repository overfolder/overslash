<script lang="ts">
	import type { Identity } from '$lib/types';

	let {
		data
	}: { data: { requestedName: string; identity: Identity | null; identities: Identity[] } } =
		$props();

	const ident = $derived(data.identity);
	const owner = $derived(ident ? data.identities.find((i) => i.id === ident.owner_id) ?? null : null);
	const children = $derived(
		ident ? data.identities.filter((i) => i.parent_id === ident.id) : []
	);
</script>

<svelte:head><title>{data.requestedName} · Agents · Overslash</title></svelte:head>

<section class="page">
	<a class="back" href="/agents">← Back to agents</a>

	{#if !ident}
		<div class="empty">
			<h1>Agent not found</h1>
			<p>No agent named <span class="mono">{data.requestedName}</span> in this org.</p>
		</div>
	{:else}
		<header class="header">
			<div>
				<h1>{ident.name}</h1>
				<p class="muted">{ident.kind === 'sub_agent' ? 'Sub-agent' : 'Agent'}</p>
			</div>
		</header>

		<div class="card">
			<div class="row">
				<span class="label">Kind</span>
				<span>{ident.kind}</span>
			</div>
			<div class="row">
				<span class="label">Owner</span>
				{#if owner}
					<a class="link" href={`/users/${encodeURIComponent(owner.name)}`}>{owner.name}</a>
				{:else}
					<span class="muted">—</span>
				{/if}
			</div>
			<div class="row">
				<span class="label">Parent</span>
				{#if ident.parent_id}
					<span class="mono muted">{ident.parent_id}</span>
				{:else}
					<span class="muted">—</span>
				{/if}
			</div>
			<div class="row">
				<span class="label">Inherit permissions</span>
				<span>{ident.inherit_permissions ? 'Yes' : 'No'}</span>
			</div>
			<div class="row">
				<span class="label">UUID</span>
				<span class="mono muted">{ident.id}</span>
			</div>
		</div>

		{#if children.length > 0}
			<div class="card">
				<h2>Sub-agents</h2>
				<ul class="agent-list">
					{#each children as c (c.id)}
						<li>
							<a class="link" href={`/agents/${encodeURIComponent(c.name)}`}>{c.name}</a>
							<span class="muted small">· {c.kind}</span>
						</li>
					{/each}
				</ul>
			</div>
		{/if}
	{/if}
</section>

<style>
	.page {
		max-width: 820px;
	}
	.back {
		display: inline-block;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-decoration: none;
		margin-bottom: 0.75rem;
	}
	.header {
		margin-bottom: 1rem;
	}
	h1 {
		font: var(--text-h1);
		margin: 0;
	}
	h2 {
		margin: 0 0 0.5rem;
		font-size: 0.95rem;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.25rem;
		margin-bottom: 0.9rem;
		display: flex;
		flex-direction: column;
		gap: 0.55rem;
	}
	.row {
		display: flex;
		gap: 0.8rem;
		font-size: 0.88rem;
	}
	.label {
		min-width: 170px;
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.small {
		font-size: 0.8rem;
	}
	.link {
		color: var(--color-primary, #6366f1);
		text-decoration: none;
	}
	.link:hover {
		text-decoration: underline;
	}
	.agent-list {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 2rem;
		text-align: center;
		color: var(--color-text-muted);
	}
	.empty h1 {
		font-size: 1.05rem;
		margin: 0 0 0.4rem;
		color: var(--color-text);
	}
	.empty p {
		margin: 0;
		font-size: 0.9rem;
	}
</style>
