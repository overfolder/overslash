<script lang="ts">
	import { sidebarCollapsed } from '$lib/stores/shell';
	import { NAV_ITEMS, ADMIN_NAV_ITEMS, SETTINGS_NAV_ITEM } from './nav-items';
	import Logo from './Logo.svelte';
	import NavItem from './NavItem.svelte';
	import ProfileAvatar from './ProfileAvatar.svelte';

	let {
		user,
		isAdmin = false
	}: { user: { name?: string; email?: string } | null; isAdmin?: boolean } = $props();

	function toggle() {
		sidebarCollapsed.update((c) => !c);
	}

	const collapsed = $derived($sidebarCollapsed);
</script>

<aside class="sidebar" class:collapsed>
	<div class="top">
		<Logo {collapsed} />
	</div>

	<nav class="nav">
		{#each NAV_ITEMS as item (item.href)}
			<NavItem href={item.href} label={item.label} icon={item.icon} {collapsed} />
		{/each}

		{#if isAdmin}
			{#if !collapsed}<div class="section-label">ADMIN</div>{:else}<div class="divider"></div>{/if}
			{#each ADMIN_NAV_ITEMS as item (item.href)}
				<NavItem href={item.href} label={item.label} icon={item.icon} {collapsed} />
			{/each}
		{/if}
	</nav>

	<div class="footer">
		{#if isAdmin}
			<NavItem
				href={SETTINGS_NAV_ITEM.href}
				label={SETTINGS_NAV_ITEM.label}
				icon={SETTINGS_NAV_ITEM.icon}
				{collapsed}
			/>
		{/if}
		<button class="collapse-btn" type="button" onclick={toggle} aria-label="Toggle sidebar">
			{collapsed ? '»' : '«'}
		</button>
		{#if user}
			<ProfileAvatar name={user.name ?? ''} email={user.email ?? ''} showName={!collapsed} />
		{/if}
	</div>
</aside>

<style>
	.sidebar {
		width: var(--sidebar-width-expanded, 240px);
		background: var(--color-surface);
		border-right: 1px solid var(--color-border);
		display: flex;
		flex-direction: column;
		padding: 1rem 0.75rem;
		gap: 1rem;
		position: fixed;
		top: 0;
		left: 0;
		bottom: 0;
		z-index: 10;
		transition: width 0.15s ease;
	}
	.sidebar.collapsed {
		width: var(--sidebar-width-collapsed, 64px);
		padding: 1rem 0.5rem;
	}
	.top {
		padding: 0.25rem 0.25rem 0.5rem;
	}
	.nav {
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
		flex: 1;
		min-height: 0;
		overflow-y: auto;
	}
	.section-label {
		font-size: 0.6875rem;
		font-weight: 600;
		letter-spacing: 0.06em;
		color: var(--color-text-muted);
		padding: 0.75rem 0.75rem 0.25rem;
	}
	.divider {
		height: 1px;
		background: var(--color-border);
		margin: 0.5rem 0.25rem;
	}
	.footer {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		border-top: 1px solid var(--color-border);
		padding-top: 0.5rem;
	}
	.collapse-btn {
		background: transparent;
		border: none;
		color: var(--color-text-muted);
		cursor: pointer;
		padding: 0.4rem;
		border-radius: 6px;
		font-size: 0.9rem;
	}
	.collapse-btn:hover {
		background: var(--color-neutral-100, var(--color-border));
		color: var(--color-text);
	}

	@media (max-width: 768px) {
		.sidebar {
			display: none;
		}
	}
</style>
