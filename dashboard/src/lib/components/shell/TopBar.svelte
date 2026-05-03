<script lang="ts">
	import { page } from '$app/stores';
	import { pageTitleFromPath } from './nav-items';
	import NotificationBell from './NotificationBell.svelte';
	import ThemeToggle from './ThemeToggle.svelte';
	import ProfileAvatar from './ProfileAvatar.svelte';

	let {
		user,
		isInstanceAdmin = false
	}: {
		user: { name?: string; email?: string } | null;
		isInstanceAdmin?: boolean;
	} = $props();

	const title = $derived(pageTitleFromPath($page.url.pathname));
</script>

<header class="topbar">
	<h1 class="title">{title}</h1>
	<div class="actions">
		<NotificationBell />
		<ThemeToggle />
		{#if user}
			<div class="user-block">
				<ProfileAvatar name={user.name ?? ''} email={user.email ?? ''} showName />
				{#if isInstanceAdmin}
					<span class="instance-badge" title="Instance admin">⚡ Instance</span>
				{/if}
			</div>
		{/if}
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
	.user-block {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		max-width: 240px;
		min-width: 0;
		margin-left: 0.5rem;
	}
	.instance-badge {
		font-size: 0.65rem;
		font-weight: 600;
		letter-spacing: 0.04em;
		padding: 2px 6px;
		border-radius: 999px;
		background: var(--color-neutral-100, var(--color-border));
		color: var(--color-text-muted);
		white-space: nowrap;
		flex-shrink: 0;
	}
</style>
