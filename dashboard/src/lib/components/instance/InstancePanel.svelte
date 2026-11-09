<script lang="ts">
	// The Instance Admin panel (`/instance/<section>`): a scope strip, a docked
	// sub-nav mirroring Org Settings, and one section page. Section styles that
	// every page shares (heading, toolbar, table card) live here as :global
	// rules under `.instance` so the sections stay markup-only.
	import { page } from '$app/state';
	import { INSTANCE_GROUPS, instanceGroupOf, instanceHref } from './sections.ts';
	import OrgsSection from './OrgsSection.svelte';
	import AdminsSection from './AdminsSection.svelte';
	import ConfigSection from './ConfigSection.svelte';
	import AuditSection from './AuditSection.svelte';

	let { section }: { section: string } = $props();

	const currentOrg = $derived(
		(page.data.user?.org_name as string | undefined) ?? 'your current org'
	);
	const host = $derived(page.url.hostname);
	const group = $derived(instanceGroupOf(section)?.label ?? '');
</script>

<div class="instance">
	<div class="scope" role="note">
		<svg
			width="14"
			height="14"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			stroke-width="1.5"
			stroke-linecap="round"
			stroke-linejoin="round"
			aria-hidden="true"
			><path
				d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
			/></svg
		>
		<span><b>Instance scope.</b> Nothing here belongs to <b>{currentOrg}</b>, your current org.</span>
		<span class="sep" aria-hidden="true">·</span>
		<span>Changes need a recent sign-in.</span>
	</div>
	<div class="docked">
		<aside class="dock" aria-label="Instance sections">
			<div class="dock-title">Instance</div>
			<div class="dock-sub">{host}</div>
			<nav class="subnav">
				{#each INSTANCE_GROUPS as g (g.label)}
					<div class="subnav-group">{g.label}</div>
					{#each g.sections as s (s.id)}
						{#if s.later}
							<span class="later-item" aria-disabled="true"
								>{s.label}<span class="later">Later</span></span
							>
						{:else}
							<a
								href={instanceHref(s.id)}
								class:on={section === s.id}
								aria-current={section === s.id ? 'page' : undefined}>{s.label}</a
							>
						{/if}
					{/each}
				{/each}
			</nav>
		</aside>
		<div class="page" data-group={group}>
			{#if section === 'admins'}
				<AdminsSection />
			{:else if section === 'config'}
				<ConfigSection />
			{:else if section === 'audit'}
				<AuditSection />
			{:else}
				<OrgsSection />
			{/if}
		</div>
	</div>
</div>

<style>
	.scope {
		display: flex;
		align-items: center;
		gap: 10px;
		flex-wrap: wrap;
		padding: 8px 32px;
		background: var(--color-surface);
		border-bottom: 1px solid var(--color-border);
		font: var(--text-body-sm);
		color: var(--color-text-secondary);
	}
	.scope b {
		font-weight: 600;
		color: var(--color-text);
	}
	.scope .sep {
		color: var(--color-text-placeholder);
	}
	.docked {
		display: grid;
		grid-template-columns: 220px minmax(0, 1fr);
		align-items: start;
	}
	.dock {
		position: sticky;
		top: 0;
		height: calc(100vh - var(--topbar-height) - var(--env-bar-height, 0px) - 37px);
		overflow-y: auto;
		background: var(--color-surface);
		border-right: 1px solid var(--color-border);
		padding: 20px 10px 24px;
	}
	.dock-title {
		font: var(--text-h3);
		color: var(--color-text-heading);
		padding: 0 10px 2px;
	}
	.dock-sub {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		padding: 0 10px 4px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.subnav {
		display: flex;
		flex-direction: column;
		gap: 1px;
	}
	.subnav-group {
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--color-text-muted);
		padding: 16px 10px 4px;
	}
	.subnav a,
	.later-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 8px;
		padding: 6px 10px;
		border-radius: 6px;
		font: var(--text-label);
		color: var(--color-text-secondary);
		text-decoration: none;
	}
	.subnav a:hover {
		background: color-mix(in srgb, var(--color-text) 6%, transparent);
		color: var(--color-text);
	}
	.subnav a.on {
		background: var(--color-primary-bg);
		color: var(--color-primary);
		font-weight: 500;
	}
	.later-item {
		color: var(--color-text-muted);
		cursor: default;
	}
	.later {
		font: var(--text-label-sm);
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: 9999px;
		padding: 0 6px;
	}
	.page {
		max-width: 1100px;
		width: 100%;
		padding: 24px 32px 64px;
	}

	/* ── Shared section styles ─────────────────────────────────────── */
	.instance :global(.head) {
		display: flex;
		align-items: flex-end;
		justify-content: space-between;
		gap: 16px;
		flex-wrap: wrap;
		margin-bottom: 20px;
	}
	.instance :global(.group) {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		margin-bottom: 4px;
	}
	.instance :global(h1) {
		font: var(--text-h1);
		margin: 0;
		color: var(--color-text-heading);
	}
	.instance :global(.desc) {
		font: var(--text-body);
		color: var(--color-text-secondary);
		margin: 6px 0 0;
		max-width: 640px;
		text-wrap: pretty;
	}
	.instance :global(.toolbar) {
		display: flex;
		align-items: center;
		gap: 10px;
		flex-wrap: wrap;
		margin-bottom: 12px;
	}
	.instance :global(.toolbar .search) {
		flex: 1 1 260px;
		min-width: 0;
		padding: 7px 10px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		color: var(--color-text);
		font: var(--text-body);
	}
	.instance :global(.select) {
		font: var(--text-label);
		color: var(--color-text);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 7px 10px;
		background: var(--color-surface);
	}
	.instance :global(.check) {
		display: inline-flex;
		gap: 6px;
		align-items: center;
		font: var(--text-label);
		color: var(--color-text);
	}
	.instance :global(.card) {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
	}
	.instance :global(.table-box) {
		overflow-x: auto;
	}
	.instance :global(.table-box table) {
		width: 100%;
		min-width: 860px;
		border-collapse: collapse;
		font-size: 13px;
	}
	.instance :global(.table-box th) {
		text-align: left;
		font: var(--text-label-sm);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		padding: 10px 14px;
		border-bottom: 1px solid var(--color-border);
	}
	.instance :global(.table-box td) {
		padding: 10px 14px;
		border-top: 1px solid var(--color-border-subtle);
		vertical-align: middle;
		color: var(--color-text);
	}
	.instance :global(.table-box tbody tr:first-child td) {
		border-top: 0;
	}
	.instance :global(.num) {
		font-variant-numeric: tabular-nums;
	}
	.instance :global(.muted) {
		color: var(--color-text-muted);
	}
	.instance :global(.time) {
		color: var(--color-text-secondary);
		white-space: nowrap;
	}
	.instance :global(.act) {
		text-align: right;
		white-space: nowrap;
	}
	.instance :global(.empty) {
		text-align: center;
		padding: 32px;
		color: var(--color-text-muted);
	}
	.instance :global(.empty.error) {
		color: var(--color-danger);
	}
	.instance :global(.foot) {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
		flex-wrap: wrap;
		padding: 10px 14px;
		border-top: 1px solid var(--color-border);
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		background: var(--color-sidebar);
		border-radius: 0 0 10px 10px;
	}
	.instance :global(.sr-only) {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}
	.instance :global(.page .btn) {
		display: inline-flex;
		align-items: center;
		padding: 8px 14px;
		border-radius: 8px;
		font: var(--text-body-medium);
		cursor: pointer;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		text-decoration: none;
	}
	.instance :global(.page .btn:hover:not(:disabled)) {
		background: color-mix(in srgb, var(--color-text) 4%, var(--color-surface));
	}
	.instance :global(.page .btn:disabled) {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.instance :global(.page .btn-sm) {
		padding: 5px 10px;
		font: var(--text-label);
	}
	.instance :global(.page .btn-primary) {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	.instance :global(.page .btn-primary:hover:not(:disabled)) {
		background: var(--color-primary);
		filter: brightness(1.05);
	}
	.instance :global(.page .btn-danger-outline) {
		color: var(--color-danger);
		border-color: color-mix(in srgb, var(--color-danger) 40%, var(--color-border));
	}

	@media (max-width: 900px) {
		.scope {
			padding: 8px 16px;
		}
		.scope .sep {
			display: none;
		}
		.docked {
			grid-template-columns: minmax(0, 1fr);
		}
		.dock {
			position: static;
			height: auto;
			border-right: 0;
			border-bottom: 1px solid var(--color-border);
			padding: 12px 16px;
		}
		.dock-title,
		.dock-sub,
		.subnav-group,
		.later-item {
			display: none;
		}
		.subnav {
			flex-direction: row;
			flex-wrap: wrap;
			gap: 4px;
		}
		.page {
			padding: 20px 16px 48px;
		}
	}
</style>
