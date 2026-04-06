<script lang="ts">
	import { page } from '$app/stores';
	import { NAV_ITEMS, ADMIN_NAV_ITEMS, isActive } from './nav-items';
	import ProfileAvatar from './ProfileAvatar.svelte';

	let {
		user,
		isAdmin = false
	}: { user: { name?: string; email?: string } | null; isAdmin?: boolean } = $props();

	const items = $derived(isAdmin ? [...NAV_ITEMS, ...ADMIN_NAV_ITEMS] : NAV_ITEMS);
</script>

<nav class="tabbar">
	{#each items as item (item.href)}
		<a
			href={item.href}
			class="tab"
			class:active={isActive($page.url.pathname, item.href)}
			aria-label={item.label}
		>
			<span class="icon">{item.icon}</span>
			<span class="label">{item.label}</span>
		</a>
	{/each}
	{#if user}
		<div class="tab profile">
			<ProfileAvatar name={user.name ?? ''} email={user.email ?? ''} />
		</div>
	{/if}
</nav>

<style>
	.tabbar {
		display: none;
		position: fixed;
		left: 0;
		right: 0;
		bottom: 0;
		height: 64px;
		background: var(--color-surface);
		border-top: 1px solid var(--color-border);
		z-index: 20;
		justify-content: space-around;
		align-items: stretch;
		padding: 0 0.25rem;
	}
	@media (max-width: 768px) {
		.tabbar {
			display: flex;
		}
	}
	.tab {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 2px;
		text-decoration: none;
		color: var(--color-text-muted);
		font-size: 0.65rem;
		padding: 0.25rem 0.1rem;
	}
	.tab .icon {
		font-size: 1.1rem;
	}
	.tab.active {
		color: var(--color-primary);
	}
	.tab .label {
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		max-width: 100%;
	}
	.tab.profile {
		padding: 0;
	}
</style>
