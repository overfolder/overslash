<!--
	The chrome-less card both public, token-gated pages sit inside:
	`/secrets/provide/[req_id]` and `/services/setup/[req_id]`.

	Extracted because the two are one handshake in two framings, and a hundred
	lines of copied CSS is how two framings become two designs. What varies is
	the content; what does not is the shell, the typography and the shared
	primitives — the metadata rows, the viewer banner, the error box and the
	buttons — which is why those are styled here with `:global` rather than
	redeclared in each page.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	let { children }: { children: Snippet } = $props();
</script>

<div class="page">
	<div class="card">
		<div class="brand">Overslash</div>
		{@render children()}
	</div>
</div>

<style>
	.page {
		min-height: 100vh;
		background: var(--color-bg);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 2.5rem;
		max-width: 540px;
		width: 100%;
		box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
	}
	.brand {
		font-weight: 700;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		letter-spacing: 0.05em;
		text-transform: uppercase;
		margin-bottom: 0.75rem;
	}

	/* The shared vocabulary of both pages. `:global` because the markup is the
	   caller's — a wrapper cannot scope styles onto a slot's contents, and the
	   alternative is the copy-paste this component exists to remove. */
	.card :global(h1) {
		margin: 0 0 0.5rem;
		font-size: 1.4rem;
		color: var(--color-text);
	}
	.card :global(.lead) {
		margin: 0 0 1.25rem;
		color: var(--color-text-muted);
	}
	.card :global(code) {
		font-family: var(--font-mono);
		font-size: 0.9em;
		background: var(--color-bg);
		padding: 0.1rem 0.35rem;
		border-radius: 4px;
	}
	.card :global(.meta) {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.card :global(.meta .row) {
		display: flex;
		justify-content: space-between;
		gap: 1rem;
		font-size: 0.85rem;
	}
	.card :global(.meta .k) {
		color: var(--color-text-muted);
		flex: none;
	}
	.card :global(.meta .v) {
		color: var(--color-text);
		text-align: right;
		overflow-wrap: anywhere;
	}
	.card :global(.error) {
		background: rgba(230, 56, 54, 0.1);
		color: var(--color-error, #e63836);
		padding: 0.5rem 0.75rem;
		border-radius: 6px;
		font-size: 0.85rem;
		margin-bottom: 0.75rem;
	}
	.card :global(.viewer-banner) {
		background: rgba(60, 140, 90, 0.08);
		border: 1px solid rgba(60, 140, 90, 0.25);
		color: var(--color-text);
		padding: 0.65rem 0.85rem;
		border-radius: 8px;
		font-size: 0.82rem;
		margin-bottom: 1rem;
		line-height: 1.45;
	}
	.card :global(.viewer-banner.warn) {
		background: rgba(235, 170, 50, 0.1);
		border-color: rgba(235, 170, 50, 0.35);
	}
	.card :global(a) {
		color: var(--color-primary);
		font-weight: 600;
	}
	.card :global(.actions) {
		display: flex;
		gap: 0.75rem;
		margin-bottom: 1rem;
	}
	.card :global(.btn) {
		flex: 1;
		padding: 0.7rem 1rem;
		border-radius: 8px;
		font: inherit;
		font-weight: 600;
		cursor: pointer;
		border: 1px solid transparent;
	}
	.card :global(.btn.primary) {
		background: var(--color-primary);
		color: #fff;
	}
	.card :global(.btn.primary:hover:not(:disabled)) {
		background: var(--color-primary-hover, #4f45c2);
	}
	.card :global(.btn.secondary) {
		background: transparent;
		border-color: var(--color-border);
		color: var(--color-text);
	}
	.card :global(.btn.secondary:hover:not(:disabled)) {
		background: var(--color-border);
	}
	.card :global(.btn:disabled) {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.card :global(.footnote) {
		font-size: 0.78rem;
		color: var(--color-text-muted);
		margin: 1rem 0 0.5rem;
	}
	.card :global(.note) {
		font-size: 0.75rem;
		color: var(--color-text-muted);
		margin: 0.5rem 0 0;
		line-height: 1.4;
	}
</style>
