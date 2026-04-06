<script lang="ts">
	import '../app.css';
	import type { Snippet } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { session } from '$lib/session';

	let { children, data }: { children: Snippet; data: { user: any } } = $props();

	const isLogin = $derived($page.url.pathname === '/login');

	async function signOut() {
		try {
			await session.post('/auth/logout');
		} catch {}
		await goto('/login');
	}
</script>

{#if isLogin}
	{@render children()}
{:else}
	<div class="app">
		<nav class="sidebar">
			<div class="logo">
				<span class="logo-icon">&#x2F;&#x2F;</span>
				<span class="logo-text">overslash</span>
			</div>
			<div class="nav-links">
				<a href="/profile" class="nav-item">
					<span class="nav-icon">&#x1D56;</span>
					Profile
				</a>
			</div>
			{#if data?.user}
				<div class="user-block">
					<div class="user-name">{data.user.name}</div>
					<div class="user-email">{data.user.email}</div>
					<button class="signout-btn" onclick={signOut}>Sign out</button>
				</div>
			{/if}
		</nav>
		<main class="content">
			{@render children()}
		</main>
	</div>
{/if}

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

	.nav-icon {
		font-size: 1.1rem;
	}

	.content {
		flex: 1;
		padding: 2rem 3rem;
		overflow-y: auto;
	}

	.user-block {
		margin-top: auto;
		padding: 0.75rem;
		border-top: 1px solid var(--color-border);
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.user-name {
		font-size: 0.9rem;
		font-weight: 600;
		color: var(--color-text);
	}

	.user-email {
		font-size: 0.75rem;
		color: var(--color-text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.signout-btn {
		margin-top: 0.5rem;
		background: transparent;
		border: 1px solid var(--color-border);
		color: var(--color-text-muted);
		padding: 0.4rem 0.6rem;
		border-radius: 6px;
		font-size: 0.8rem;
		cursor: pointer;
	}

	.signout-btn:hover {
		background: var(--color-border);
		color: var(--color-text);
	}
</style>
