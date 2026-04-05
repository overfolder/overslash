<script lang="ts">
	import '../app.css';
	import type { Snippet } from 'svelte';
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { session } from '$lib/session';
	import type { MeIdentity } from '$lib/session';

	let { children }: { children: Snippet } = $props();

	let identity: MeIdentity | null = $state(null);

	onMount(async () => {
		try {
			identity = await session.get<MeIdentity>('/auth/me/identity');
		} catch {
			// Not authenticated — admin nav hidden
		}
	});

	const adminLinks = [
		{ href: '/admin/templates', label: 'Templates', icon: '\u2630' },
		{ href: '/admin/services', label: 'Services', icon: '\u26A1' },
		{ href: '/admin/groups', label: 'Groups', icon: '\u2691' },
		{ href: '/admin/webhooks', label: 'Webhooks', icon: '\u21C4' },
		{ href: '/admin/settings', label: 'Settings', icon: '\u2699' }
	];
</script>

<div class="app">
	<nav class="sidebar">
		<div class="logo">
			<span class="logo-icon">&#x2F;&#x2F;</span>
			<span class="logo-text">overslash</span>
		</div>
		<div class="nav-links">
			<a href="/profile" class="nav-item" class:active={$page.url.pathname === '/profile'}>
				<span class="nav-icon">&#x1D56;</span>
				Profile
			</a>
		</div>
		{#if identity?.kind === 'user'}
			<div class="nav-section">
				<span class="nav-section-label">Admin</span>
				<div class="nav-links">
					{#each adminLinks as link}
						<a
							href={link.href}
							class="nav-item"
							class:active={$page.url.pathname.startsWith(link.href)}
						>
							<span class="nav-icon">{link.icon}</span>
							{link.label}
						</a>
					{/each}
				</div>
			</div>
		{/if}
	</nav>
	<main class="content">
		{@render children()}
	</main>
</div>

<style>
	.app {
		display: flex;
		min-height: 100vh;
	}

	.sidebar {
		width: 220px;
		background: var(--color-surface);
		border-right: 1px solid var(--color-border);
		padding: 1.5rem 1rem;
		display: flex;
		flex-direction: column;
		gap: 2rem;
	}

	.logo {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0 0.75rem;
	}

	.logo-icon {
		font-size: 1.5rem;
		font-weight: 700;
		color: var(--color-primary);
		font-family: var(--font-mono);
	}

	.logo-text {
		font-size: 1.1rem;
		font-weight: 600;
		color: var(--color-text);
	}

	.nav-section {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.nav-section-label {
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--color-text-muted);
		padding: 0 0.75rem;
	}

	.nav-links {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.nav-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.6rem 0.75rem;
		border-radius: 6px;
		color: var(--color-text-muted);
		font-size: 0.9rem;
		transition: background 0.15s, color 0.15s;
	}

	.nav-item:hover {
		background: var(--color-border);
		color: var(--color-text);
	}

	.nav-item.active {
		background: rgba(99, 102, 241, 0.15);
		color: var(--color-primary);
	}

	.nav-icon {
		font-size: 1.1rem;
	}

	.content {
		flex: 1;
		padding: 2rem 3rem;
		overflow-y: auto;
	}
</style>
