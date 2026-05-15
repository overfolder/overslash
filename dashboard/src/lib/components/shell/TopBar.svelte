<script lang="ts">
	import { page } from '$app/stores';
	import { pageTitleFromPath } from './nav-items';
	import NotificationBell from './NotificationBell.svelte';
	import ThemeToggle from './ThemeToggle.svelte';
	import ProfileAvatar from './ProfileAvatar.svelte';

	let {
		user,
		isInstanceAdmin = false,
		onMenu = () => {}
	}: {
		user: { name?: string; email?: string } | null;
		isInstanceAdmin?: boolean;
		onMenu?: () => void;
	} = $props();

	const title = $derived(pageTitleFromPath($page.url.pathname));
</script>

<header class="topbar">
	<div class="left">
		<button
			class="hamburger"
			type="button"
			aria-label="Open menu"
			onclick={onMenu}
		>
			<span class="bars"><span></span><span></span><span></span></span>
		</button>
		<h1 class="title">{title}</h1>
	</div>
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
		gap: 0.5rem;
	}
	.left {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		min-width: 0;
	}
	.title {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text);
		margin: 0;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
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
	.hamburger {
		display: none;
		width: 36px;
		height: 36px;
		border: 0;
		background: transparent;
		border-radius: 8px;
		color: var(--color-text);
		cursor: pointer;
		flex: none;
		align-items: center;
		justify-content: center;
		padding: 0;
	}
	.hamburger:hover {
		background: var(--color-neutral-100, rgba(0, 0, 0, 0.04));
	}
	.bars {
		display: inline-flex;
		flex-direction: column;
		gap: 4px;
	}
	.bars span {
		display: block;
		width: 18px;
		height: 2px;
		background: currentColor;
		border-radius: 1px;
	}

	/* Tablet: shrink horizontal padding, hide instance badge text. */
	@media (max-width: 1024px) {
		.topbar {
			padding: 0 1rem;
		}
		.user-block {
			max-width: 160px;
		}
	}
	/* Mobile: hamburger appears, user block shows avatar only. */
	@media (max-width: 767px) {
		.topbar {
			padding: 0 0.75rem;
			height: 52px;
			gap: 0.25rem;
		}
		.hamburger {
			display: inline-flex;
		}
		.title {
			font-size: 0.95rem;
		}
		.instance-badge {
			display: none;
		}
		.user-block {
			max-width: 44px;
			margin-left: 0.25rem;
		}
		/* Hide the avatar's name/email block so only the avatar circle remains. */
		.user-block :global(.name-block) {
			display: none;
		}
	}
</style>
