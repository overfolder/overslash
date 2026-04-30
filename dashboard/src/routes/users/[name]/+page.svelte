<script lang="ts">
	import type { Identity } from '$lib/types';

	let {
		data
	}: { data: { requestedName: string; identity: Identity | null; identities: Identity[] } } =
		$props();

	const ident = $derived(data.identity);
	const agents = $derived(
		ident ? data.identities.filter((i) => i.owner_id === ident.id) : []
	);

	function providerLabel(p?: string | null): string {
		if (!p) return '—';
		const map: Record<string, string> = { google: 'Google', github: 'GitHub', oidc: 'OIDC' };
		return map[p.toLowerCase()] ?? p;
	}
</script>

<svelte:head><title>{data.requestedName} · Users · Overslash</title></svelte:head>

<section class="page">
	<a class="back" href="/members">← Back to members</a>

	{#if !ident}
		<div class="empty">
			<h1>User not found</h1>
			<p>No user named <span class="mono">{data.requestedName}</span> in this org.</p>
		</div>
	{:else}
		<header class="header">
			<div class="avatar">{ident.name.slice(0, 1).toUpperCase()}</div>
			<div>
				<h1>{ident.name}</h1>
				<p class="muted">{ident.email ?? '—'}</p>
			</div>
		</header>

		<div class="card">
			<div class="row">
				<span class="label">Kind</span>
				<span>{ident.kind}</span>
			</div>
			<div class="row">
				<span class="label">Identity provider</span>
				<span>{providerLabel(ident.provider)}</span>
			</div>
			<div class="row">
				<span class="label">External ID</span>
				<span class="mono">{ident.external_id ?? '—'}</span>
			</div>
			<div class="row">
				<span class="label">UUID</span>
				<span class="mono muted">{ident.id}</span>
			</div>
		</div>

		<div class="card">
			<h2>Agents owned by {ident.name}</h2>
			{#if agents.length === 0}
				<p class="muted">No agents yet.</p>
			{:else}
				<ul class="agent-list">
					{#each agents as a (a.id)}
						<li>
							<a class="link" href={`/agents/${a.id}`}>{a.name}</a>
							<span class="muted small">· {a.kind}</span>
						</li>
					{/each}
				</ul>
			{/if}
		</div>
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
		display: flex;
		align-items: center;
		gap: 0.85rem;
		margin-bottom: 1rem;
	}
	.avatar {
		width: 48px;
		height: 48px;
		border-radius: 999px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		display: flex;
		align-items: center;
		justify-content: center;
		font-weight: 600;
		font-size: 1.1rem;
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
		min-width: 140px;
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
