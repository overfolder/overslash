<!--
	The one avatar in the app: a circular picture with an initials fallback.

	Every user identity already carries a `picture` — the IdP's `picture` /
	`avatar_url` claim, refreshed on every sign-in (see
	crates/overslash-api/src/routes/auth/provisioning.rs). It is hotlinked
	straight from the provider rather than proxied, so two things matter:

	- `referrerpolicy="no-referrer"`, so we never hand Google or GitHub the URL
	  of the page the reader is on.
	- the initials are always rendered *underneath* the image rather than as an
	  `{:else}` branch. `onerror` covers a URL that fails, but a third-party
	  host that is merely slow — or hanging — fires neither `load` nor `error`,
	  and an `{:else}` would leave a blank coloured disc for as long as it takes.
	  Painting the initials first means the worst case is initials, never
	  nothing; the image covers them opaquely the moment it decodes.
-->
<script lang="ts">
	import { identityInitials } from '$lib/identityDisplay';

	let {
		picture = null,
		name = '',
		email = null,
		size = 32,
		title,
		badge
	}: {
		/** The IdP's picture URL. Absent, empty or broken falls back to initials. */
		picture?: string | null;
		name?: string;
		email?: string | null;
		/** Diameter in px. Drives the initials type size and the badge too. */
		size?: number;
		title?: string;
		/** Rendered over the bottom-left of the circle at half the diameter —
		 *  a provider tile on a connection, a service icon later. */
		badge?: import('svelte').Snippet;
	} = $props();

	const initials = $derived(identityInitials({ name, email }));

	// Which URL failed, rather than a bare `failed` flag: comparing against the
	// current `picture` makes a new URL retry on its own, with no $effect
	// writing state that the same render reads.
	let failedSrc = $state<string | null>(null);
	const showImage = $derived(!!picture && picture !== failedSrc);
</script>

<span class="avatar" style:--avatar-size="{size}px" {title}>
	<span class="disc">
		{initials}
		{#if showImage}
			<img
				src={picture}
				alt=""
				referrerpolicy="no-referrer"
				loading="lazy"
				onerror={() => (failedSrc = picture ?? null)}
			/>
		{/if}
	</span>
	{#if badge}
		<span class="badge">{@render badge()}</span>
	{/if}
</span>

<style>
	.avatar {
		position: relative;
		display: inline-flex;
		flex: none;
		width: var(--avatar-size);
		height: var(--avatar-size);
	}
	.disc {
		position: relative;
		display: flex;
		align-items: center;
		justify-content: center;
		width: 100%;
		height: 100%;
		border-radius: 50%;
		overflow: hidden;
		background: var(--color-primary);
		color: #fff;
		/* Scales with the circle so one component covers 20px table rows and
		   72px profile headers: 0.4 keeps two characters inside at both ends. */
		font-size: calc(var(--avatar-size) * 0.4);
		font-weight: 600;
		line-height: 1;
		user-select: none;
	}
	.disc img {
		position: absolute;
		inset: 0;
		width: 100%;
		height: 100%;
		object-fit: cover;
		display: block;
		/* Opaque, so it hides the initials underneath rather than blending
		   with them once it decodes. */
		background: var(--color-primary);
	}
	.badge {
		position: absolute;
		left: 0;
		bottom: 0;
		display: flex;
		align-items: center;
		justify-content: center;
		width: calc(var(--avatar-size) / 2);
		height: calc(var(--avatar-size) / 2);
		/* A ring in the page colour, so the badge reads as a separate shape
		   instead of blending into whatever it overlaps. The radius follows
		   the shape the caller renders inside it — a circle by default, and
		   `--avatar-badge-radius: 30%` for a rounded-square provider tile,
		   whose corners would otherwise poke through a circular ring. */
		border-radius: var(--avatar-badge-radius, 50%);
		box-shadow: 0 0 0 2px var(--color-surface);
		background: var(--color-surface);
	}
</style>
