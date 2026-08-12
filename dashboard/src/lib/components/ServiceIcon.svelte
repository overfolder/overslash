<!--
	The mark for a service or template: its icon, with the letter tile
	underneath.

	`icon_url` comes resolved from the API — a built-in asset we serve
	ourselves (`/icons/<key>.svg`, usually implicit from the template key) or an
	https:// URL a template author supplied. Anything the API could not vouch
	for arrives absent, so this component never has to judge a URL.

	Two details are borrowed from `Avatar`, for the same reasons:

	- the letter tile is rendered *underneath* the image, not as an `{:else}`.
	  `onerror` covers a URL that fails outright, but a third-party host that is
	  merely slow — or hanging — fires neither `load` nor `error`, and a branch
	  would leave an empty square for as long as that takes.
	- `failedSrc` records *which* URL failed rather than a bare flag, so a new
	  `src` retries on its own without an `$effect` writing state the same
	  render reads.

	The image sits on a light ground in both themes. A brand mark carries its
	own colours and several of the ones we ship are near-black (GitHub, X,
	Notion); on the dark theme's tile they would be invisible, and we cannot
	restyle them because they are served cross-origin and rendered in an `<img>`.
-->
<script lang="ts">
	import ServiceTile from '$lib/components/approval/ServiceTile.svelte';

	let {
		src = null,
		name,
		size = 28
	}: {
		/** Resolved icon URL. Absent or broken falls back to the letter tile. */
		src?: string | null;
		/** Display name — drives the fallback letter. */
		name: string;
		size?: number;
	} = $props();

	let failedSrc = $state<string | null>(null);
	const showImage = $derived(!!src && src !== failedSrc);
</script>

<span class="icon" style:width="{size}px" style:height="{size}px">
	<ServiceTile {name} {size} />
	{#if showImage}
		<img
			{src}
			alt=""
			referrerpolicy="no-referrer"
			loading="lazy"
			decoding="async"
			onerror={() => (failedSrc = src ?? null)}
		/>
	{/if}
</span>

<style>
	.icon {
		position: relative;
		display: inline-flex;
		flex: none;
	}
	.icon img {
		position: absolute;
		inset: 0;
		width: 100%;
		height: 100%;
		/* `contain`, not `cover`: these are logos with their own clearspace,
		   and cropping one to fill the square would clip the mark. */
		object-fit: contain;
		display: block;
		border-radius: 8px;
		border: 1px solid var(--color-border);
		background: #f6f6f8;
		padding: 2px;
		box-sizing: border-box;
	}
</style>
