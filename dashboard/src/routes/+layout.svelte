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
	import { startEventStream, stopEventStream } from '$lib/stores/events.svelte';
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

	// Height reserved for the environment ribbon; 0 in prod. Applied as an inline
	// CSS var on the shell wrappers below (not via an $effect), so the offset is
	// present in the very first render and the sidebar/topbar don't shift down a
	// frame after load. It cascades to Sidebar/TopBar, which read the same var.
	const envBarHeight = $derived(env.isProd ? '0px' : '24px');

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

	// The Live Map wants the whole pane: `.content`'s padding would frame a
	// full-bleed canvas, and its `overflow-y: auto` would let the graph push
	// the page taller instead of being clipped to it.
	const fullBleed = $derived($page.url.pathname.startsWith('/map'));

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

	// The stream shares notification polling's lifecycle: both want an
	// authenticated session, and `standalone` already covers the surfaces that
	// don't have one (/login, /secrets/provide, /oauth/consent).
	$effect(() => {
		if (standalone) {
			stopNotificationPolling();
			stopEventStream();
		} else {
			startNotificationPolling();
			startEventStream();
		}
		return () => {
			stopNotificationPolling();
			stopEventStream();
		};
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

<!-- One declaration of --env-bar-height for the whole shell. `display: contents`
     adds no box, but the custom property still cascades to every descendant —
     the ribbon and the .app/.standalone offsets read the same value, so the bar
     height and the reserved space can never drift apart. -->
<div class="env-scope" style:--env-bar-height={envBarHeight}>
	{#if !env.isProd}
		<DevEnvBanner name={env.name} />
	{/if}

	{#if standalone}
		<div class="standalone">
			{@render children()}
		</div>
	{:else}
		<div class="app" class:full-bleed={fullBleed} style:--sidebar-width={sidebarWidth}>
			<Sidebar
				{isAdmin}
				{isInstanceAdmin}
				memberships={data?.user?.memberships ?? []}
				invitations={data?.user?.invitations ?? []}
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
				<main class="content" class:full-bleed={fullBleed}>
					{@render children()}
				</main>
			</div>
			<MobileTabBar user={data?.user ?? null} {isAdmin} />
		</div>
	{/if}
</div>

<Toaster />

<style>
	.env-scope {
		/* No box of its own — just a cascade root for --env-bar-height. */
		display: contents;
	}
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
	/* A full-bleed page is clipped to the viewport rather than growing past it.
	   `min-height: 100vh` on both .app and .main-col means the shell is
	   normally 100vh *plus* the env ribbon's padding — fine when the page
	   scrolls, but it pushes a fixed-height canvas's bottom overlays off
	   screen. Pin the height instead and let the flex column divide it; the
	   global `box-sizing: border-box` keeps the ribbon inside the 100vh. */
	.app.full-bleed {
		height: 100vh;
		min-height: 0;
	}
	.app.full-bleed .main-col {
		height: 100%;
		min-height: 0;
	}
	.content.full-bleed {
		display: flex;
		padding: 0;
		min-height: 0;
		overflow: hidden;
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
