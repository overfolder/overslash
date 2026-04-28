<!--
  Owner badge for the secrets list / detail header. Looks up the slot
  owner's identity from the layout's identity map and renders a glyph +
  label, with a tooltip showing the full identity path on agent owners.
-->
<script lang="ts">
	import type { Identity } from '$lib/types';

	let {
		ownerId,
		identityById,
		currentUserId
	}: {
		ownerId: string | null;
		identityById: Map<string, Identity>;
		currentUserId?: string;
	} = $props();

	const ident = $derived(ownerId ? identityById.get(ownerId) ?? null : null);
	const isAgent = $derived(
		ident !== null && (ident.kind === 'agent' || ident.kind === 'sub_agent')
	);
	const isSelf = $derived(ident !== null && ident.kind === 'user' && ident.id === currentUserId);
	const label = $derived(
		ident === null
			? ownerId
				? 'unknown'
				: 'system'
			: isSelf
				? `${ident.name} (you)`
				: ident.name
	);

	// Walk up `owner_id` to render `parent / child / grandchild` for agent
	// tooltips. Caps at 4 hops so a deep chain doesn't blow up the tooltip.
	const path = $derived.by(() => {
		if (!ident || !isAgent) return null;
		const parts: string[] = [ident.name];
		let cursor: Identity | null = ident;
		for (let i = 0; i < 4 && cursor?.owner_id; i++) {
			const next = identityById.get(cursor.owner_id);
			if (!next) break;
			parts.unshift(next.name);
			cursor = next;
		}
		return parts.join(' / ');
	});
</script>

<span class={isAgent ? 'owner owner-agent' : 'owner'} title={path ?? undefined}>
	<span
		class="glyph"
		style:background={isAgent ? 'var(--badge-bg-primary)' : 'var(--neutral-100)'}
		style:color={isAgent ? 'var(--color-primary)' : 'var(--neutral-500)'}
	>{isAgent ? '⊟' : '◉'}</span>
	<span class="label">{label}</span>
	{#if isAgent && path}
		<span class="tooltip" role="tooltip">
			<span class="tooltip-label">Identity path</span>
			<span class="tooltip-path">{path}</span>
		</span>
	{/if}
</span>

<style>
	.owner {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		position: relative;
	}
	.owner-agent {
		cursor: help;
	}
	.glyph {
		width: 18px;
		height: 18px;
		border-radius: 4px;
		flex: none;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		font-size: 11px;
		font-weight: 600;
		font-family: var(--font-mono);
	}
	.label {
		font-size: 13px;
	}
	.tooltip {
		position: absolute;
		bottom: calc(100% + 8px);
		left: 0;
		background: var(--neutral-900);
		color: #f0f1f2;
		padding: 8px 10px;
		border-radius: 8px;
		box-shadow: var(--shadow-md);
		white-space: nowrap;
		pointer-events: none;
		opacity: 0;
		transform: translateY(2px);
		transition: opacity 0.12s ease, transform 0.12s ease;
		z-index: 30;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.tooltip::after {
		content: '';
		position: absolute;
		top: 100%;
		left: 16px;
		border: 5px solid transparent;
		border-top-color: var(--neutral-900);
	}
	.tooltip-label {
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--neutral-500);
		font-weight: 600;
	}
	.tooltip-path {
		font-family: var(--font-mono);
		font-size: 12px;
		color: #f0f1f2;
	}
	.owner-agent:hover .tooltip,
	.owner-agent:focus-within .tooltip {
		opacity: 1;
		transform: translateY(0);
	}
</style>
