<script lang="ts">
	import { session, type MembershipSummary } from '$lib/session';

	type Props = {
		memberships: MembershipSummary[];
		currentOrgId: string;
		collapsed?: boolean;
	};

	let { memberships, currentOrgId, collapsed = false }: Props = $props();

	let open = $state(false);
	let switching = $state(false);
	let error: string | null = $state(null);

	const current = $derived(memberships.find((m) => m.org_id === currentOrgId));
	const personalMemberships = $derived(memberships.filter((m) => m.is_personal));
	const orgMemberships = $derived(memberships.filter((m) => !m.is_personal));

	async function selectOrg(orgId: string) {
		if (orgId === currentOrgId || switching) return;
		switching = true;
		error = null;
		try {
			const res = await session.post<{ redirect_to?: string }>('/auth/switch-org', {
				org_id: orgId
			});
			// Hard-reload on the returned URL (different subdomain for corp orgs).
			// If the server didn't give one (self-hosted single-host), just reload
			// the current page to pick up the new session cookie.
			if (res?.redirect_to) {
				window.location.href = res.redirect_to;
			} else {
				window.location.reload();
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to switch org';
			switching = false;
		}
	}

	function toggle() {
		if (memberships.length <= 1) return;
		open = !open;
	}
</script>

<div class="switcher" class:collapsed>
	<button
		class="trigger"
		type="button"
		onclick={toggle}
		aria-haspopup="listbox"
		aria-expanded={open}
		disabled={memberships.length <= 1}
	>
		{#if current}
			<span class="name">{collapsed ? current.slug.charAt(0).toUpperCase() : current.name}</span>
			{#if !collapsed && current.is_bootstrap}
				<span class="badge" title="Bootstrap admin — drop once your IdP-backed account exists"
					>breakglass</span
				>
			{/if}
		{:else}
			<span class="name">{collapsed ? '?' : 'No org'}</span>
		{/if}
		{#if !collapsed && memberships.length > 1}
			<span class="chev" aria-hidden="true">▾</span>
		{/if}
	</button>

	{#if open && !collapsed}
		<div class="menu" role="listbox">
			{#if personalMemberships.length > 0}
				<div class="group-label">Personal</div>
				{#each personalMemberships as m (m.org_id)}
					<button
						class="item"
						class:active={m.org_id === currentOrgId}
						type="button"
						role="option"
						aria-selected={m.org_id === currentOrgId}
						disabled={switching}
						onclick={() => selectOrg(m.org_id)}
					>
						<span class="item-name">{m.name}</span>
					</button>
				{/each}
			{/if}

			{#if orgMemberships.length > 0}
				<div class="group-label">Orgs</div>
				{#each orgMemberships as m (m.org_id)}
					<button
						class="item"
						class:active={m.org_id === currentOrgId}
						type="button"
						role="option"
						aria-selected={m.org_id === currentOrgId}
						disabled={switching}
						onclick={() => selectOrg(m.org_id)}
					>
						<span class="item-name">{m.name}</span>
						{#if m.is_bootstrap}
							<span class="badge-small" title="Bootstrap (breakglass) admin">●</span>
						{/if}
					</button>
				{/each}
			{/if}

			{#if error}
				<div class="error">{error}</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.switcher {
		position: relative;
	}
	.trigger {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 0.4rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		padding: 0.4rem 0.5rem;
		cursor: pointer;
		color: var(--color-text);
		font-size: 0.875rem;
		text-align: left;
	}
	.trigger:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}
	.trigger:disabled {
		cursor: default;
		opacity: 0.9;
	}
	.name {
		flex: 1;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.chev {
		color: var(--color-text-muted);
		font-size: 0.7rem;
	}
	.badge {
		font-size: 0.65rem;
		padding: 0.05rem 0.35rem;
		background: var(--color-warning-soft, #fff3cd);
		color: var(--color-warning, #8a6d3b);
		border-radius: 10px;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.badge-small {
		color: var(--color-warning, #8a6d3b);
	}
	.menu {
		position: absolute;
		bottom: calc(100% + 4px);
		left: 0;
		right: 0;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		padding: 0.25rem;
		z-index: 20;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
		max-height: 360px;
		overflow-y: auto;
	}
	.group-label {
		font-size: 0.65rem;
		font-weight: 600;
		letter-spacing: 0.06em;
		color: var(--color-text-muted);
		padding: 0.35rem 0.5rem 0.15rem;
		text-transform: uppercase;
	}
	.item {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 0.4rem;
		background: transparent;
		border: none;
		padding: 0.4rem 0.5rem;
		text-align: left;
		color: var(--color-text);
		cursor: pointer;
		border-radius: 4px;
		font-size: 0.85rem;
	}
	.item:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}
	.item.active {
		background: var(--color-neutral-100, var(--color-border));
		font-weight: 600;
	}
	.item-name {
		flex: 1;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.error {
		padding: 0.4rem 0.5rem;
		color: var(--color-danger, #b00020);
		font-size: 0.8rem;
	}
	.switcher.collapsed .trigger {
		justify-content: center;
		padding: 0.4rem;
	}
	.switcher.collapsed .name {
		flex: initial;
	}
</style>
