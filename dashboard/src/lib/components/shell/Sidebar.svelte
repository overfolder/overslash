<script lang="ts">
	import { page } from '$app/stores';
	import { sidebarCollapsed } from '$lib/stores/shell';
	import { viewport } from '$lib/stores/viewport';
	import {
		NAV_ITEMS,
		ADMIN_NAV_ITEMS,
		LIVE_MAP_NAV_ITEM,
		SETTINGS_NAV_ITEM,
		pickActiveHref
	} from './nav-items';
	import Logo from './Logo.svelte';
	import NavItem from './NavItem.svelte';
	import OrgSwitcher from './OrgSwitcher.svelte';
	import PendingInvites from './PendingInvites.svelte';
	import CreateOrgModal from '$lib/components/CreateOrgModal.svelte';
	import type { PendingInvitation } from '$lib/api/account';
	import type { MembershipSummary } from '$lib/session';
	import type { BuildInfo } from '$lib/types';
	import { buildLabel, buildTitle, hasCommit } from '$lib/api/version';

	let {
		isAdmin = false,
		isInstanceAdmin = false,
		memberships = [],
		invitations = [],
		currentOrgId = '',
		mobileOpen = false,
		onCloseMobile = () => {},
		buildInfo = null
	}: {
		isAdmin?: boolean;
		isInstanceAdmin?: boolean;
		memberships?: MembershipSummary[];
		/** Orgs that invited this user but which they haven't joined yet. */
		invitations?: PendingInvitation[];
		currentOrgId?: string;
		mobileOpen?: boolean;
		onCloseMobile?: () => void;
		/** Build identity of the API, or null until it resolves. Passed in
		 *  rather than fetched here so this component stays inert in tests and
		 *  screenshot scenarios. */
		buildInfo?: BuildInfo | null;
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

	// The Live Map only exists on a build that emits `action.*` events, and
	// that answer arrives with `/v1/version` rather than with the page. The
	// item therefore appears a beat after first paint — acceptable for a
	// dev-only view, and cheaper than blocking nav on a fetch.
	const liveMap = $derived(buildInfo?.live_map === true);

	// `/org` (Settings) is a prefix of `/org/groups` (Groups), so per-item
	// isActive() lights up both. Pick the longest match across every visible
	// item once and pass it down to NavItem so only one is highlighted.
	const allItems = $derived([
		...NAV_ITEMS,
		...(liveMap ? [LIVE_MAP_NAV_ITEM] : []),
		...(isAdmin ? ADMIN_NAV_ITEMS : []),
		...(isAdmin ? [SETTINGS_NAV_ITEM] : [])
	]);

	const activeHref = $derived(pickActiveHref($page.url.pathname, allItems));

	let createOrgOpen = $state(false);

	// Build stamp. The collapsed rail shows the version alone — the short SHA
	// would win the 64px of space without being the thing anyone recognises —
	// and both widths surface the full commit on hover.
	const label = $derived(buildLabel(buildInfo, collapsed));
	const title = $derived(buildTitle(buildInfo, true));

	let buildCopied = $state(false);
	let copyResetTimer: ReturnType<typeof setTimeout> | undefined;

	async function copyBuild() {
		if (!buildInfo || !navigator.clipboard) return;
		try {
			await navigator.clipboard.writeText(
				hasCommit(buildInfo) ? buildInfo.commit : buildInfo.version
			);
			buildCopied = true;
			clearTimeout(copyResetTimer);
			copyResetTimer = setTimeout(() => (buildCopied = false), 1500);
		} catch {
			// Clipboard denied (insecure origin, permission) — the full SHA is
			// still readable in the tooltip.
		}
	}

	$effect(() => () => clearTimeout(copyResetTimer));
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

		{#if liveMap}
			<NavItem
				href={LIVE_MAP_NAV_ITEM.href}
				label={LIVE_MAP_NAV_ITEM.label}
				icon={LIVE_MAP_NAV_ITEM.icon}
				{collapsed}
				{activeHref}
			/>
		{/if}

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
		<PendingInvites {invitations} {collapsed} />
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
		{#if buildInfo}
			<button class="build" type="button" {title} onclick={copyBuild}>
				{buildCopied ? 'Copied' : label}
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
		top: var(--env-bar-height, 0);
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
	.build {
		background: transparent;
		border: none;
		color: var(--color-text-muted);
		cursor: pointer;
		font-size: 0.7rem;
		font-variant-numeric: tabular-nums;
		letter-spacing: 0.02em;
		padding: 0.15rem 0.25rem 0;
		text-align: center;
		/* The collapsed rail is 64px wide; never let a long version string
		   push the sidebar or wrap onto a second line. */
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.build:hover {
		color: var(--color-text);
	}
</style>
