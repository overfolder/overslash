<script lang="ts">
	import { page } from '$app/stores';
	import { pageTitleFromPath } from './nav-items';
	import NotificationBell from './NotificationBell.svelte';
	import ThemeToggle from './ThemeToggle.svelte';

	let { onSignOut }: { onSignOut: () => void } = $props();

	const title = $derived(pageTitleFromPath($page.url.pathname));
</script>

<header class="topbar">
	<h1 class="title">{title}</h1>
	<div class="actions">
		<NotificationBell />
		<ThemeToggle />
		<button class="signout" type="button" onclick={onSignOut}>Sign out</button>
	</div>
</header>

<style>
	.topbar {
		height: var(--topbar-height, 56px);
		background: var(--color-surface);
		border-bottom: 1px solid var(--color-border);
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0 1.5rem;
		position: sticky;
		top: 0;
		z-index: 5;
	}
	.title {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text);
		margin: 0;
	}
	.actions {
		display: flex;
		align-items: center;
		gap: 0.25rem;
	}
	.signout {
		margin-left: 0.5rem;
		background: transparent;
		border: 1px solid var(--color-border);
		color: var(--color-text-muted);
		padding: 0.35rem 0.7rem;
		border-radius: 6px;
		font-size: 0.8rem;
		cursor: pointer;
	}
	.signout:hover {
		background: var(--color-neutral-100, var(--color-border));
		color: var(--color-text);
	}
</style>
