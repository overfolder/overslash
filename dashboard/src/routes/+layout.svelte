<script lang="ts">
	import '../app.css';
	import type { Snippet } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { session, type MeIdentity } from '$lib/session';
	import {
		sidebarCollapsed,
		theme,
		startNotificationPolling,
		stopNotificationPolling,
		hydrateUserPreferences
	} from '$lib/stores/shell';
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
	const collapsed = $derived($sidebarCollapsed);

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

	async function signOut() {
		try {
			await session.post('/auth/logout');
		} catch {
			/* ignore */
		}
		await goto('/login');
	}
</script>

{#if standalone}
	{@render children()}
{:else}
	<div
		class="app"
		style:--sidebar-width={collapsed
			? 'var(--sidebar-width-collapsed, 64px)'
			: 'var(--sidebar-width-expanded, 240px)'}
	>
		<Sidebar
			user={data?.user ?? null}
			{isAdmin}
			memberships={data?.user?.memberships ?? []}
			currentOrgId={data?.user?.org_id ?? ''}
		/>
		<div class="main-col">
			<TopBar onSignOut={signOut} />
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
	@media (max-width: 768px) {
		.main-col {
			margin-left: 0;
			padding-bottom: 64px;
		}
		.content {
			padding: 1rem;
		}
	}
</style>
