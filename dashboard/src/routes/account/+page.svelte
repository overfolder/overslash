<script lang="ts">
	import { onMount } from 'svelte';
	import { session, type MembershipSummary, type MeIdentity } from '$lib/session';

	let me: MeIdentity | null = $state(null);
	let memberships: MembershipSummary[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);
	let dropping: string | null = $state(null);

	onMount(async () => {
		try {
			me = await session.get<MeIdentity>('/auth/me/identity');
			memberships = me?.memberships ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load account';
		} finally {
			loading = false;
		}
	});

	async function dropMembership(orgId: string, label: string) {
		if (!confirm(`Drop your membership in ${label}? You'll need to sign in via that org's IdP to come back.`))
			return;
		dropping = orgId;
		error = null;
		try {
			await session.delete(`/v1/account/memberships/${orgId}`);
			memberships = memberships.filter((m) => m.org_id !== orgId);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to drop membership';
		} finally {
			dropping = null;
		}
	}

	async function switchTo(orgId: string) {
		try {
			const res = await session.post<{ redirect_to?: string }>('/auth/switch-org', {
				org_id: orgId
			});
			if (res?.redirect_to) {
				window.location.href = res.redirect_to;
			} else {
				window.location.reload();
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to switch org';
		}
	}
</script>

<section class="page">
	<header>
		<h1>Account</h1>
		<p class="subtitle">Your Overslash account and org memberships.</p>
	</header>

	{#if loading}
		<p>Loading…</p>
	{:else if error}
		<p class="error">{error}</p>
	{:else if me}
		<div class="card">
			<h2>Profile</h2>
			<dl>
				<dt>Name</dt>
				<dd>{me.name}</dd>
				<dt>Email</dt>
				<dd>{me.email}</dd>
				{#if me.user_id}
					<dt>User ID</dt>
					<dd><code>{me.user_id}</code></dd>
				{/if}
			</dl>
		</div>

		<div class="card">
			<h2>Organizations</h2>
			{#if memberships.length === 0}
				<p class="muted">No memberships yet.</p>
			{:else}
				<ul class="memberships">
					{#each memberships as m (m.org_id)}
						<li>
							<div class="m-head">
								<strong>{m.name}</strong>
								<span class="role">{m.role}</span>
								{#if m.is_personal}
									<span class="tag">personal</span>
								{/if}
							</div>
							<div class="m-actions">
								<button type="button" onclick={() => switchTo(m.org_id)} disabled={m.org_id === me.org_id}>
									{m.org_id === me.org_id ? 'Current' : 'Switch'}
								</button>
								{#if !m.is_personal}
									<button
										type="button"
										class="danger"
										disabled={dropping === m.org_id}
										onclick={() => dropMembership(m.org_id, m.name)}
									>
										{dropping === m.org_id ? 'Dropping…' : 'Leave'}
									</button>
								{/if}
							</div>
						</li>
					{/each}
				</ul>
			{/if}
		</div>
	{/if}
</section>

<style>
	.page {
		max-width: 720px;
		margin: 0 auto;
	}
	header {
		margin-bottom: 1.5rem;
	}
	h1 {
		margin: 0 0 0.25rem 0;
	}
	.subtitle {
		color: var(--color-text-muted);
		margin: 0;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 1rem 1.25rem;
		margin-bottom: 1rem;
	}
	.card h2 {
		margin: 0 0 0.75rem 0;
		font-size: 1rem;
	}
	dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		column-gap: 1rem;
		row-gap: 0.4rem;
		margin: 0;
	}
	dt {
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
	dd {
		margin: 0;
	}
	code {
		font-family: ui-monospace, SFMono-Regular, monospace;
		font-size: 0.85rem;
	}
	.memberships {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.memberships li {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.6rem 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
	}
	.m-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.role {
		color: var(--color-text-muted);
		font-size: 0.8rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.tag {
		font-size: 0.65rem;
		padding: 0.05rem 0.4rem;
		background: var(--color-neutral-100, var(--color-border));
		border-radius: 10px;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.m-actions {
		display: flex;
		gap: 0.5rem;
	}
	button {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 4px;
		padding: 0.3rem 0.65rem;
		cursor: pointer;
		font-size: 0.85rem;
	}
	button:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}
	button.danger {
		color: var(--color-danger, #b00020);
	}
	button:disabled {
		opacity: 0.6;
		cursor: default;
	}
	.error {
		color: var(--color-danger, #b00020);
	}
	.muted {
		color: var(--color-text-muted);
	}
</style>
