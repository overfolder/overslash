<script lang="ts">
	import { page } from '$app/stores';
	import { isActive } from './nav-items';
	import NavIcon, { type IconName } from './NavIcon.svelte';

	let {
		href,
		label,
		icon,
		collapsed = false,
		activeHref = null
	}: {
		href: string;
		label: string;
		icon: IconName;
		/** Rail mode: icon on top with a small label underneath. */
		collapsed?: boolean;
		// When the parent renders multiple NavItems whose hrefs are prefixes
		// of one another (e.g. /org and /org/groups), pass the parent's
		// `pickActiveHref(...)` result so only the longest match lights up.
		// Falling back to per-item isActive() preserves prior behavior.
		activeHref?: string | null;
	} = $props();

	const active = $derived(
		activeHref !== null ? href === activeHref : isActive($page.url.pathname, href)
	);
</script>

<a {href} class="nav-item" class:active class:collapsed title={collapsed ? label : undefined}>
	<span class="icon"><NavIcon name={icon} /></span>
	<span class="label">{label}</span>
</a>

<style>
	.nav-item {
		display: flex;
		align-items: center;
		gap: 0.625rem;
		padding: 0.5rem 0.75rem;
		border-radius: 8px;
		color: var(--color-text-secondary);
		font: var(--text-label);
		text-decoration: none;
		transition:
			background 0.1s,
			color 0.1s;
	}
	.nav-item:hover {
		background: color-mix(in srgb, var(--color-text) 6%, transparent);
		color: var(--color-text);
	}
	.nav-item.active {
		background: var(--color-primary-bg);
		color: var(--color-primary);
		font-weight: 500;
	}
	.icon {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 1.25rem;
		flex: none;
	}
	.label {
		flex: 1;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	/* Rail: the icon stacks over a small, still-readable label. */
	.nav-item.collapsed {
		flex-direction: column;
		gap: 4px;
		padding: 8px 0;
	}
	.nav-item.collapsed .label {
		flex: none;
		max-width: 100%;
		font-size: 10.5px;
		line-height: 13px;
		text-align: center;
		white-space: normal;
		text-wrap: balance;
	}
</style>
