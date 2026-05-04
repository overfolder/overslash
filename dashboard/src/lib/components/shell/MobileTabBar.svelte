<script lang="ts">
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { ADMIN_NAV_ITEMS, SETTINGS_NAV_ITEM, isActive, type NavItemDef } from './nav-items';

	let {
		user,
		isAdmin = false
	}: { user: { name?: string; email?: string } | null; isAdmin?: boolean } = $props();

	// Bottom bar keeps the four most-used routes; everything else lives behind
	// "More" so we don't pack 9 icons into a 390-px viewport.
	const PRIMARY_TABS: NavItemDef[] = [
		{ href: '/agents', label: 'Agents', icon: '⊟' },
		{ href: '/services', label: 'Services', icon: '◫' },
		{ href: '/approvals', label: 'Approvals', icon: '✓' }
	];

	const MORE_ITEMS: NavItemDef[] = $derived([
		{ href: '/secrets', label: 'Secrets', icon: '⚷' },
		{ href: '/audit', label: 'Audit Log', icon: '☰' },
		...(isAdmin ? ADMIN_NAV_ITEMS : []),
		...(isAdmin ? [SETTINGS_NAV_ITEM] : []),
		{ href: '/profile', label: 'Profile', icon: '◉' }
	]);

	let moreOpen = $state(false);

	// "More" is active when the current route is one of the secondary items.
	const moreActive = $derived(MORE_ITEMS.some((it) => isActive($page.url.pathname, it.href)));

	function openMore() {
		moreOpen = true;
	}
	function closeMore() {
		moreOpen = false;
	}
	function pickFromMore(href: string) {
		closeMore();
		void goto(href);
	}

	// Close the sheet on route change (any tap inside it triggers nav).
	$effect(() => {
		void $page.url.pathname;
		moreOpen = false;
	});
</script>

<nav class="tabbar" aria-label="Primary">
	{#each PRIMARY_TABS as item (item.href)}
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
	<button
		type="button"
		class="tab more-btn"
		class:active={moreActive || moreOpen}
		aria-haspopup="menu"
		aria-expanded={moreOpen}
		onclick={openMore}
	>
		<span class="icon">⋯</span>
		<span class="label">More</span>
	</button>
</nav>

{#if moreOpen}
	<button
		type="button"
		class="scrim"
		aria-label="Close menu"
		onclick={closeMore}
	></button>
	<div class="sheet" role="menu" aria-label="More">
		<div class="grabber" aria-hidden="true"></div>
		<div class="sheet-label">More</div>
		{#each MORE_ITEMS as item (item.href)}
			<button
				type="button"
				class="sheet-item"
				class:active={isActive($page.url.pathname, item.href)}
				onclick={() => pickFromMore(item.href)}
				role="menuitem"
			>
				<span class="icon">{item.icon}</span>
				<span class="label">{item.label}</span>
			</button>
		{/each}
		{#if user}
			<div class="sheet-foot">
				Signed in as <strong>{user.name || user.email}</strong>
			</div>
		{/if}
	</div>
{/if}

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
	@media (max-width: 767px) {
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
		font-size: 0.7rem;
		padding: 0.25rem 0.1rem;
		background: transparent;
		border: 0;
		cursor: pointer;
		font-family: inherit;
		-webkit-tap-highlight-color: transparent;
	}
	.tab .icon {
		font-size: 1.2rem;
		line-height: 1;
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

	.scrim {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.4);
		border: 0;
		padding: 0;
		z-index: 65;
	}
	.sheet {
		position: fixed;
		left: 0;
		right: 0;
		bottom: 0;
		z-index: 66;
		background: var(--color-surface);
		border-top-left-radius: 16px;
		border-top-right-radius: 16px;
		padding: 12px 12px calc(20px + env(safe-area-inset-bottom, 0));
		box-shadow: var(--shadow-xl);
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.grabber {
		width: 40px;
		height: 4px;
		border-radius: 2px;
		background: var(--neutral-200, var(--color-border));
		margin: 0 auto 10px;
	}
	.sheet-label {
		font-size: 0.6875rem;
		font-weight: 600;
		letter-spacing: 0.06em;
		color: var(--color-text-muted);
		text-transform: uppercase;
		padding: 4px 12px 6px;
	}
	.sheet-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		width: 100%;
		padding: 12px;
		background: transparent;
		border: 0;
		border-radius: 8px;
		font-size: 0.95rem;
		color: var(--color-text);
		text-align: left;
		cursor: pointer;
		font-family: inherit;
	}
	.sheet-item:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
	.sheet-item.active {
		background: var(--color-primary-bg, var(--primary-50));
		color: var(--color-primary);
		font-weight: 600;
	}
	.sheet-item .icon {
		font-size: 1.1rem;
		width: 1.5rem;
		text-align: center;
	}
	.sheet-foot {
		margin-top: 8px;
		padding: 10px 12px 0;
		border-top: 1px solid var(--color-border);
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
</style>
