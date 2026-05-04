<script lang="ts">
	import { page } from '$app/stores';
	import { sidebarCollapsed } from '$lib/stores/shell';
	import { viewport } from '$lib/stores/viewport';
	import { NAV_ITEMS, ADMIN_NAV_ITEMS, SETTINGS_NAV_ITEM, pickActiveHref } from './nav-items';
	import Logo from './Logo.svelte';
	import NavItem from './NavItem.svelte';
	import OrgSwitcher from './OrgSwitcher.svelte';
	import CreateOrgModal from '$lib/components/CreateOrgModal.svelte';
	import type { MembershipSummary } from '$lib/session';

	let {
		isAdmin = false,
		isInstanceAdmin = false,
		memberships = [],
		currentOrgId = '',
		mobileOpen = false,
		onCloseMobile = () => {}
	}: {
		isAdmin?: boolean;
		isInstanceAdmin?: boolean;
		memberships?: MembershipSummary[];
		currentOrgId?: string;
		mobileOpen?: boolean;
		onCloseMobile?: () => void;
	} = $props();

	function toggle() {
		sidebarCollapsed.update((c) => !c);
	}

	// On tablet, render as collapsed regardless of user preference (the user's
	// desktop preference is preserved). On mobile, the drawer is always full
	// width — labels visible — when open.
	const collapsed = $derived(
		$viewport === 'tablet' ? true : $viewport === 'mobile' ? false : $sidebarCollapsed
	);
	const isMobile = $derived($viewport === 'mobile');

	// `/org` (Settings) is a prefix of `/org/groups` (Groups), so per-item
	// isActive() lights up both. Pick the longest match across every visible
	// item once and pass it down to NavItem so only one is highlighted.
	const allItems = $derived([
		...NAV_ITEMS,
		...(isAdmin ? ADMIN_NAV_ITEMS : []),
		...(isAdmin ? [SETTINGS_NAV_ITEM] : [])
	]);
	const activeHref = $derived(pickActiveHref($page.url.pathname, allItems));

	let createOrgOpen = $state(false);
</script>

{#if isMobile}
	<button
		type="button"
		class="scrim"
		class:open={mobileOpen}
		aria-label="Close menu"
		onclick={onCloseMobile}
		tabindex={mobileOpen ? 0 : -1}
	></button>
{/if}

<aside
	class="sidebar"
	class:collapsed
	class:mobile={isMobile}
	class:open={mobileOpen}
	aria-hidden={isMobile && !mobileOpen}
>
	<div class="top">
		<Logo {collapsed} />
	</div>

	<nav class="nav">
		{#each NAV_ITEMS as item (item.href)}
			<NavItem
				href={item.href}
				label={item.label}
				icon={item.icon}
				{collapsed}
				{activeHref}
			/>
		{/each}

		{#if isAdmin}
			{#if !collapsed}<div class="section-label">ADMIN</div>{:else}<div class="divider"></div>{/if}
			{#each ADMIN_NAV_ITEMS as item (item.href)}
				<NavItem
				href={item.href}
				label={item.label}
				icon={item.icon}
				{collapsed}
				{activeHref}
			/>
			{/each}
		{/if}
	</nav>

	<div class="footer">
		{#if memberships.length > 0 && currentOrgId}
			<OrgSwitcher {memberships} {currentOrgId} {collapsed} />
		{/if}
		{#if isInstanceAdmin}
			<button
				class="create-org-btn"
				type="button"
				onclick={() => (createOrgOpen = true)}
				title="Create org"
			>
				{#if collapsed}+{:else}+ Create org{/if}
			</button>
		{/if}
		{#if isAdmin}
			<NavItem
				href={SETTINGS_NAV_ITEM.href}
				label={SETTINGS_NAV_ITEM.label}
				icon={SETTINGS_NAV_ITEM.icon}
				{collapsed}
				{activeHref}
			/>
		{/if}
		{#if !isMobile && $viewport !== 'tablet'}
			<button class="collapse-btn" type="button" onclick={toggle} aria-label="Toggle sidebar">
				{collapsed ? '»' : '«'}
			</button>
		{/if}
	</div>
</aside>

<CreateOrgModal open={createOrgOpen} onClose={() => (createOrgOpen = false)} />

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
		z-index: 30;
		transition:
			width 0.15s ease,
			transform 0.2s ease;
	}
	.sidebar.collapsed {
		width: var(--sidebar-width-collapsed, 64px);
		padding: 1rem 0.5rem;
	}
	.sidebar.mobile {
		/* Drawer: always full-label width on mobile, slide in from the left. */
		width: 280px;
		transform: translateX(-100%);
		box-shadow: var(--shadow-xl);
		z-index: 70;
	}
	.sidebar.mobile.open {
		transform: translateX(0);
	}
	.scrim {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.4);
		border: 0;
		padding: 0;
		z-index: 60;
		opacity: 0;
		pointer-events: none;
		transition: opacity 0.15s ease;
	}
	.scrim.open {
		opacity: 1;
		pointer-events: auto;
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
	.create-org-btn {
		background: transparent;
		border: 1px dashed var(--color-border);
		color: var(--color-text);
		cursor: pointer;
		padding: 0.4rem 0.6rem;
		border-radius: 6px;
		font-size: 0.85rem;
		text-align: center;
		margin: 0.25rem 0;
	}
	.create-org-btn:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
</style>
