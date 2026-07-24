<script lang="ts">
	import '../app.css';
	import type { Snippet } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import { type MeIdentity } from '$lib/session';
	import { currentEnvironment, type AppEnv } from '$lib/env';
	import { getVersion } from '$lib/api/version';
	import type { BuildInfo } from '$lib/types';
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
	import TrialBanner from '$lib/components/shell/TrialBanner.svelte';
	import DevEnvBanner from '$lib/components/shell/DevEnvBanner.svelte';
	import Toaster from '$lib/components/Toaster.svelte';

	let { children, data }: { children: Snippet; data: { user: MeIdentity | null } } = $props();

	const standalone = $derived(
		$page.url.pathname === '/login' ||
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

	// Which environment this tab is pointed at. On the server we can't know the
	// runtime host, so we assume prod (no ribbon, no favicon swap) until hydration.
	const env = $derived<AppEnv>(
		browser ? currentEnvironment() : { name: '', isProd: true }
	);

	$effect(() => {
		if (typeof document !== 'undefined') {
			document.documentElement.dataset.theme = $theme;
		}
	});

	// Reserve space for the environment ribbon. The var defaults to 0 (see the
	// `, 0` fallbacks in .app / Sidebar / TopBar), so prod is an exact no-op.
	$effect(() => {
		if (!browser) return;
		document.documentElement.style.setProperty('--env-bar-height', env.isProd ? '0px' : '24px');
	});

	// Swap the favicon for a distinct dev-tinted variant in non-prod. Repoint the
	// existing app.html <link> tags rather than appending new ones — multiple
	// same-size icon links have undefined precedence.
	$effect(() => {
		if (!browser || env.isProd) return;
		const map: Record<string, string> = {
			'favicon-16.png': 'favicon-dev-16.png',
			'favicon-32.png': 'favicon-dev-32.png',
			'apple-touch-icon.png': 'apple-touch-icon-dev.png'
		};
		const links = document.querySelectorAll<HTMLLinkElement>(
			"link[rel~='icon'], link[rel='apple-touch-icon']"
		);
		for (const link of links) {
			for (const [prod, dev] of Object.entries(map)) {
				if (link.href.includes(prod)) link.href = link.href.replace(prod, dev);
			}
		}
	});

	$effect(() => {
		if (data?.user) {
			void hydrateUserPreferences();
		}
	});

	// Build identity of the API, shown in the sidebar footer. Fetched once per
	// session rather than per navigation — it cannot change without a reload of
	// the whole page anyway. A failure leaves the footer line unrendered; an
	// unidentifiable build is not worth an error toast.
	let buildInfo = $state<BuildInfo | null>(null);
	$effect(() => {
		if (!data?.user || buildInfo) return;
		getVersion()
			.then((info) => (buildInfo = info))
			.catch(() => {});
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

{#if !env.isProd}
	<DevEnvBanner name={env.name} />
{/if}

{#if standalone}
	<div class="standalone">
		{@render children()}
	</div>
{:else}
	<div class="app" style:--sidebar-width={sidebarWidth}>
		<Sidebar
			{isAdmin}
			{isInstanceAdmin}
			memberships={data?.user?.memberships ?? []}
			currentOrgId={data?.user?.org_id ?? ''}
			mobileOpen={mobileDrawerOpen}
			onCloseMobile={() => (mobileDrawerOpen = false)}
			{buildInfo}
		/>
		<div class="main-col">
			<TopBar
				user={data?.user ?? null}
				{isInstanceAdmin}
				onMenu={() => (mobileDrawerOpen = true)}
			/>
			{#if data?.user?.trial}
				<TrialBanner trial={data.user.trial} {isAdmin} />
			{/if}
			<main class="content">
				{@render children()}
			</main>
		</div>
		<MobileTabBar user={data?.user ?? null} {isAdmin} />
	</div>
{/if}

<Toaster />

<style>
	.app,
	.standalone {
		min-height: 100vh;
		/* Offset for the environment ribbon; resolves to 0 in prod. */
		padding-top: var(--env-bar-height, 0);
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
