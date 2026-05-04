<script lang="ts">
	import '../app.css';
	import type { Snippet } from 'svelte';
	import { page } from '$app/stores';
	import { type MeIdentity } from '$lib/session';
	import {
		sidebarCollapsed,
		theme,
		startNotificationPolling,
		stopNotificationPolling,
		hydrateUserPreferences
	} from '$lib/stores/shell';
	import { viewport } from '$lib/stores/viewport';
	import Sidebar from '$lib/components/shell/Sidebar.svelte';
	import TopBar from '$lib/components/shell/TopBar.svelte';
	import MobileTabBar from '$lib/components/shell/MobileTabBar.svelte';

	let { children, data }: { children: Snippet; data: { user: MeIdentity | null } } = $props();

	const standalone = $derived(
		$page.url.pathname === '/login' ||
			$page.url.pathname.startsWith('/approvals/') ||
			$page.url.pathname.startsWith('/secrets/provide/') ||
			$page.url.pathname.startsWith('/oauth/consent')
	);
	const isAdmin = $derived(data?.user?.is_org_admin === true);
	const isInstanceAdmin = $derived(data?.user?.is_instance_admin === true);

	// Effective sidebar width for the main content's left margin.
	//   mobile  : 0   (drawer overlays content)
	//   tablet  : 64  (sidebar visually collapsed regardless of preference)
	//   desktop : 64 / 240 depending on user preference
	const sidebarWidth = $derived(
		$viewport === 'mobile'
			? '0px'
			: $viewport === 'tablet'
				? 'var(--sidebar-width-collapsed, 64px)'
				: $sidebarCollapsed
					? 'var(--sidebar-width-collapsed, 64px)'
					: 'var(--sidebar-width-expanded, 240px)'
	);

	let mobileDrawerOpen = $state(false);

	$effect(() => {
		if (typeof document !== 'undefined') {
			document.documentElement.dataset.theme = $theme;
		}
	});

	$effect(() => {
		if (data?.user) {
			void hydrateUserPreferences();
		}
	});

	$effect(() => {
		if (standalone) {
			stopNotificationPolling();
		} else {
			startNotificationPolling();
		}
		return () => stopNotificationPolling();
	});

	// Close the drawer when the route changes (any in-drawer nav click) or
	// when the viewport grows past mobile.
	$effect(() => {
		// Track pathname so this effect re-runs on navigation.
		void $page.url.pathname;
		mobileDrawerOpen = false;
	});
	$effect(() => {
		if ($viewport !== 'mobile') mobileDrawerOpen = false;
	});

	// Lock body scroll while the drawer is open.
	$effect(() => {
		if (typeof document === 'undefined') return;
		document.body.style.overflow = mobileDrawerOpen ? 'hidden' : '';
		return () => {
			document.body.style.overflow = '';
		};
	});
</script>

{#if standalone}
	{@render children()}
{:else}
	<div class="app" style:--sidebar-width={sidebarWidth}>
		<Sidebar
			{isAdmin}
			{isInstanceAdmin}
			memberships={data?.user?.memberships ?? []}
			currentOrgId={data?.user?.org_id ?? ''}
			mobileOpen={mobileDrawerOpen}
			onCloseMobile={() => (mobileDrawerOpen = false)}
		/>
		<div class="main-col">
			<TopBar
				user={data?.user ?? null}
				{isInstanceAdmin}
				onMenu={() => (mobileDrawerOpen = true)}
			/>
			<main class="content">
				{@render children()}
			</main>
		</div>
		<MobileTabBar user={data?.user ?? null} {isAdmin} />
	</div>
{/if}

<style>
	.app {
		min-height: 100vh;
	}
	.main-col {
		margin-left: var(--sidebar-width);
		min-height: 100vh;
		display: flex;
		flex-direction: column;
		transition: margin-left 0.15s ease;
	}
	.content {
		flex: 1;
		padding: 1.5rem 2rem;
		overflow-y: auto;
	}
	@media (max-width: 1024px) {
		.content {
			padding: 1.25rem 1.5rem;
		}
	}
	@media (max-width: 767px) {
		.main-col {
			margin-left: 0;
			padding-bottom: 64px;
		}
		.content {
			padding: 1rem;
		}
	}
</style>
