<!--
	The mark for an agent: its MCP client's logo, over a colour bar that is the
	agent's own.

	The two halves answer different questions, which is why there are two of
	them. The logo says *what kind of thing this is* — Claude Code, Cursor, Zed
	— and is shared by every agent running on that client. The bar says *which*
	agent this is: three colours hashed from the agent's id, so a row of five
	Claude Code agents is still five distinguishable rows. See DECISIONS.md D70.

	Both arrive resolved from the API (`icon_url`, `icon_stripe`), so this
	component never hashes anything or judges a URL. An agent whose client we do
	not recognise already carries the generic bot glyph by the time it gets
	here; `iconUrl` is absent only in the pathological case where even that is
	missing from the build, and `ServiceIcon` degrades to a letter tile.
-->
<script lang="ts">
	import ServiceIcon from '$lib/components/ServiceIcon.svelte';

	let {
		iconUrl = null,
		stripe = null,
		name,
		size = 28,
		clientLabel = null
	}: {
		/** Resolved client mark. Absent or broken falls back to the letter tile. */
		iconUrl?: string | null;
		/** Three `#rrggbb` strings. Absent renders no bar — e.g. a user identity. */
		stripe?: string[] | null;
		/** Agent name — drives the fallback letter and the hover text. */
		name: string;
		/** Width of the tile in px. The bar matches it. */
		size?: number;
		/** What the client calls itself, appended to the tooltip when known. */
		clientLabel?: string | null;
	} = $props();

	const title = $derived(clientLabel ? `${name} · ${clientLabel}` : name);
</script>

<span class="agent-avatar" style:--tile-size="{size}px" {title}>
	<ServiceIcon src={iconUrl} {name} {size} />
	{#if stripe && stripe.length}
		<!-- Decorative: the name and the tooltip already carry the identity, and
		     three hex colours read aloud would be noise. -->
		<span class="stripe" aria-hidden="true">
			{#each stripe as colour, i (i)}
				<span class="seg" style:background={colour}></span>
			{/each}
		</span>
	{/if}
</span>

<style>
	.agent-avatar {
		display: inline-flex;
		flex-direction: column;
		align-items: center;
		flex: none;
		gap: 2px;
		width: var(--tile-size);
	}
	.stripe {
		display: flex;
		width: 100%;
		height: 3px;
		border-radius: 2px;
		overflow: hidden;
		/* The colours come straight off a hash, so a segment can land on very
		   nearly the page background in one theme or the other. An inset hairline
		   keeps the bar's silhouette readable without altering the colours
		   themselves — which have to stay exact, since matching two agents by
		   eye is the entire point. */
		box-shadow: inset 0 0 0 1px var(--color-border);
	}
	.seg {
		flex: 1 1 0;
		min-width: 0;
	}
</style>
