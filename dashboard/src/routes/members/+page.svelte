<script lang="ts">
	import type { Identity, ApiKeySummary } from './types';

	let { data }: { data: { identities: Identity[]; apiKeys: ApiKeySummary[] } } = $props();

	let query = $state('');
	let selectedId: string | null = $state(null);

	const users = $derived(data.identities.filter((i) => i.kind === 'user'));

	const agentCountByUser = $derived.by(() => {
		const m = new Map<string, number>();
		for (const i of data.identities) {
			if ((i.kind === 'agent' || i.kind === 'sub_agent') && i.owner_id) {
				m.set(i.owner_id, (m.get(i.owner_id) ?? 0) + 1);
			}
		}
		return m;
	});

	const apiKeyCountByUser = $derived.by(() => {
		const m = new Map<string, number>();
		for (const k of data.apiKeys) {
			if (k.identity_id && !k.revoked_at) {
				m.set(k.identity_id, (m.get(k.identity_id) ?? 0) + 1);
			}
		}
		return m;
	});

	const hasImpersonateKeyByUser = $derived.by(() => {
		const m = new Map<string, boolean>();
		for (const k of data.apiKeys) {
			if (k.identity_id && !k.revoked_at && k.scopes?.includes('impersonate')) {
				m.set(k.identity_id, true);
			}
		}
		return m;
	});

	const filtered = $derived.by(() => {
		const q = query.trim().toLowerCase();
		if (!q) return users;
		return users.filter(
			(u) =>
				u.name.toLowerCase().includes(q) || (u.email ?? '').toLowerCase().includes(q)
		);
	});

	const selected = $derived(filtered.find((u) => u.id === selectedId) ?? null);

	function initials(name: string): string {
		return name
			.split(/\s+/)
			.filter(Boolean)
			.slice(0, 2)
			.map((p) => p[0]?.toUpperCase() ?? '')
			.join('');
	}

	function providerLabel(p: string | null): string {
		if (!p) return '—';
		const map: Record<string, string> = {
			google: 'Google',
			github: 'GitHub',
			oidc: 'OIDC'
		};
		return map[p.toLowerCase()] ?? p;
	}

	function providerClass(p: string | null): string {
		if (!p) return 'badge badge-neutral';
		const k = p.toLowerCase();
		if (k === 'google') return 'badge badge-success';
		if (k === 'github') return 'badge badge-primary';
		return 'badge badge-neutral';
	}

	function fmtDate(iso: string): string {
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '—';
		return d.toLocaleDateString(undefined, {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	}

	function fmtDateTime(iso: string): string {
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '—';
		return d.toLocaleString();
	}
</script>

<svelte:head>
	<title>Members · Overslash</title>
</svelte:head>

<section class="page">
	<header class="page-header">
		<div>
			<h1>Members</h1>
			<p class="subtitle">
				{users.length}
				{users.length === 1 ? 'member' : 'members'} in this org
			</p>
		</div>
	</header>

	<div class="search">
		<input
			type="search"
			placeholder="Search by name or email…"
			bind:value={query}
			aria-label="Search members"
		/>
	</div>

	{#if users.length === 0}
		<div class="empty">
			<div class="empty-title">No members yet</div>
			<div class="empty-body">
				Members are created automatically the first time someone signs in to your
				organization.
			</div>
		</div>
	{:else if filtered.length === 0}
		<div class="empty">
			<div class="empty-title">No members match “{query}”</div>
			<div class="empty-body">Try a different name or email.</div>
		</div>
	{:else}
		<div class="card">
			<table class="members-table">
				<thead>
					<tr>
						<th class="col-user">User</th>
						<th>Email</th>
						<th>IdP</th>
						<th class="num">Agents</th>
						<th class="num">API keys</th>
						<th>Created</th>
					</tr>
				</thead>
				<tbody>
					{#each filtered as u (u.id)}
						<tr
							class:selected={selectedId === u.id}
							onclick={() => (selectedId = u.id)}
						>
							<td class="col-user">
								<div class="user-cell">
									{#if u.picture}
										<img class="avatar" src={u.picture} alt="" referrerpolicy="no-referrer" />
									{:else}
										<div class="avatar avatar-fallback">{initials(u.name)}</div>
									{/if}
									<span class="name">{u.name}</span>
								</div>
							</td>
							<td class="email">{u.email ?? '—'}</td>
							<td>
								<span class={providerClass(u.provider)}>{providerLabel(u.provider)}</span>
							</td>
							<td class="num">{agentCountByUser.get(u.id) ?? 0}</td>
							<td class="num">{apiKeyCountByUser.get(u.id) ?? 0}</td>
							<td class="muted">{fmtDate(u.created_at)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</section>

{#if selected}
	<div
		class="drawer-backdrop"
		role="presentation"
		onclick={() => (selectedId = null)}
	></div>
	<aside class="drawer" aria-label="Member detail">
		<header class="drawer-header">
			<div class="drawer-id">
				{#if selected.picture}
					<img class="avatar lg" src={selected.picture} alt="" referrerpolicy="no-referrer" />
				{:else}
					<div class="avatar avatar-fallback lg">{initials(selected.name)}</div>
				{/if}
				<div>
					<h2>{selected.name}</h2>
					<p class="muted">{selected.email ?? 'no email on file'}</p>
				</div>
			</div>
			<button class="close" onclick={() => (selectedId = null)} aria-label="Close">×</button>
		</header>

		<dl class="detail-grid">
			<dt>IdP source</dt>
			<dd><span class={providerClass(selected.provider)}>{providerLabel(selected.provider)}</span></dd>

			<dt>External ID</dt>
			<dd class="mono">{selected.external_id ?? '—'}</dd>

			<dt>Identity ID</dt>
			<dd class="mono small">{selected.id}</dd>

			<dt>Agents</dt>
			<dd>{agentCountByUser.get(selected.id) ?? 0}</dd>

			<dt>API keys</dt>
			<dd>
				{apiKeyCountByUser.get(selected.id) ?? 0}
				{#if hasImpersonateKeyByUser.get(selected.id)}
					<span class="imp-badge" title="This identity has at least one key with the 'impersonate' scope">impersonate</span>
				{/if}
			</dd>

			<dt>Created</dt>
			<dd>{fmtDateTime(selected.created_at)}</dd>
		</dl>
	</aside>
{/if}

<style>
	.page {
		max-width: 1100px;
		margin: 0 auto;
		display: flex;
		flex-direction: column;
		gap: var(--space-6);
	}

	.page-header h1 {
		font: var(--text-h1);
		color: var(--color-text-heading);
		margin: 0;
	}
	.subtitle {
		font: var(--text-body);
		color: var(--color-text-secondary);
		margin: var(--space-1) 0 0;
	}

	.search input {
		width: 100%;
		max-width: 360px;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-surface);
		color: var(--color-text);
		font: var(--text-body);
	}
	.search input:focus {
		outline: none;
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px var(--color-primary-bg);
	}

	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-sm);
		overflow: hidden;
	}

	.members-table {
		width: 100%;
		border-collapse: collapse;
		font: var(--text-body);
		color: var(--color-text);
	}
	.members-table thead th {
		background: var(--color-bg);
		text-align: left;
		font: var(--text-label);
		color: var(--color-text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--color-border);
	}
	.members-table tbody tr {
		border-bottom: 1px solid var(--color-border-subtle);
		cursor: pointer;
		transition: background 0.1s ease;
	}
	.members-table tbody tr:last-child {
		border-bottom: none;
	}
	.members-table tbody tr:hover,
	.members-table tbody tr.selected {
		background: var(--color-bg);
	}
	.members-table td {
		padding: var(--space-3) var(--space-4);
		vertical-align: middle;
	}
	.num {
		text-align: right;
		font-variant-numeric: tabular-nums;
	}
	.muted {
		color: var(--color-text-secondary);
	}
	.email {
		color: var(--color-text);
	}

	.user-cell {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}
	.name {
		font: var(--text-body-medium);
		color: var(--color-text-heading);
	}

	.avatar {
		width: 32px;
		height: 32px;
		border-radius: var(--radius-pill);
		object-fit: cover;
		background: var(--color-bg);
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}
	.avatar.lg {
		width: 56px;
		height: 56px;
		font-size: 20px;
	}
	.avatar-fallback {
		background: var(--primary-50);
		color: var(--primary-600);
		font: var(--text-label);
		text-transform: uppercase;
	}

	.badge {
		display: inline-block;
		padding: 2px var(--space-2);
		border-radius: var(--radius-pill);
		font: var(--text-label-sm);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.badge-success {
		background: color-mix(in srgb, var(--success-500) calc(var(--badge-opacity) * 100%), transparent);
		color: var(--success-500);
	}
	.badge-primary {
		background: var(--color-primary-bg);
		color: var(--color-primary);
	}
	.badge-neutral {
		background: var(--color-border-subtle);
		color: var(--color-text-secondary);
	}

	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: var(--radius-lg);
		padding: var(--space-12) var(--space-6);
		text-align: center;
	}
	.empty-title {
		font: var(--text-h3);
		color: var(--color-text-heading);
		margin-bottom: var(--space-2);
	}
	.empty-body {
		font: var(--text-body);
		color: var(--color-text-secondary);
		max-width: 420px;
		margin: 0 auto;
	}

	.drawer-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.25);
		z-index: 40;
	}
	.drawer {
		position: fixed;
		top: 0;
		right: 0;
		bottom: 0;
		width: min(420px, 100vw);
		background: var(--color-surface);
		border-left: 1px solid var(--color-border);
		box-shadow: var(--shadow-xl);
		z-index: 41;
		padding: var(--space-6);
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: var(--space-6);
	}
	.drawer-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-3);
	}
	.drawer-id {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}
	.drawer-id h2 {
		font: var(--text-h2);
		color: var(--color-text-heading);
		margin: 0;
	}
	.drawer-id p {
		margin: var(--space-1) 0 0;
		font: var(--text-body-sm);
	}
	.close {
		background: none;
		border: none;
		font-size: 28px;
		line-height: 1;
		color: var(--color-text-secondary);
		cursor: pointer;
		padding: 0 var(--space-2);
	}
	.close:hover {
		color: var(--color-text-heading);
	}

	.detail-grid {
		display: grid;
		grid-template-columns: 120px 1fr;
		gap: var(--space-3) var(--space-4);
		margin: 0;
	}
	.detail-grid dt {
		font: var(--text-label);
		color: var(--color-text-secondary);
	}
	.detail-grid dd {
		font: var(--text-body);
		color: var(--color-text);
		margin: 0;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.small {
		font-size: 12px;
		word-break: break-all;
	}
	.imp-badge {
		display: inline-block;
		margin-left: var(--space-2);
		padding: 1px var(--space-2);
		border-radius: var(--radius-pill);
		background: color-mix(in srgb, var(--warning-500, #f59e0b) 15%, transparent);
		color: var(--warning-600, #b45309);
		font: var(--text-label-sm);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		cursor: help;
	}
</style>
