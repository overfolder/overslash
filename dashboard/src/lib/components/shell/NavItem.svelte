<script lang="ts">
	import { page } from '$app/stores';
	import { isActive } from './nav-items';

	let {
		href,
		label,
		icon,
		collapsed = false
	}: { href: string; label: string; icon: string; collapsed?: boolean } = $props();

	const active = $derived(isActive($page.url.pathname, href));
</script>

<a {href} class="nav-item" class:active class:collapsed title={collapsed ? label : undefined}>
	<span class="icon">{icon}</span>
	{#if !collapsed}<span class="label">{label}</span>{/if}
</a>

<style>
	.nav-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.55rem 0.75rem;
		border-radius: 6px;
		color: var(--color-text-muted);
		font-size: 0.9rem;
		text-decoration: none;
		transition:
			background 0.15s,
			color 0.15s;
	}
	.nav-item.collapsed {
		justify-content: center;
		padding: 0.55rem 0;
	}
	.nav-item:hover {
		background: var(--color-neutral-100, var(--color-border));
		color: var(--color-text);
	}
	.nav-item.active {
		background: var(--color-primary-50, rgba(79, 70, 229, 0.1));
		color: var(--color-primary);
		font-weight: 600;
	}
	.icon {
		font-size: 1.1rem;
		width: 1.25rem;
		text-align: center;
	}
	.label {
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
</style>
