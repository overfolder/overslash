<script lang="ts">
	// One shell command, rendered so it can be copied in a single click.
	//
	// Row shape matches `services/ByocSection.svelte`'s setup rows — the other
	// place in the app where we hand the user a literal string to paste
	// somewhere else — so the two read as the same control.
	import { copyToClipboard } from '$lib/utils/clipboard';

	let {
		command,
		label = undefined,
		dense = false
	}: { command: string; label?: string; dense?: boolean } = $props();

	let copied = $state(false);
	let timer: ReturnType<typeof setTimeout> | undefined;

	async function copy() {
		// `copyToClipboard` returns false rather than throwing when the
		// Clipboard API is missing (insecure context, older browser). The
		// command stays selectable in the <code> either way, so a false just
		// means "don't flash the confirmation".
		if (!(await copyToClipboard(command))) return;
		copied = true;
		clearTimeout(timer);
		timer = setTimeout(() => (copied = false), 1500);
	}
</script>

<div class="cmd-row" class:dense>
	{#if label}
		<span class="cmd-key">{label}</span>
	{/if}
	<div class="cmd-val">
		<code class="mono">{command}</code>
		<button type="button" class="copy" onclick={copy} aria-label={label ? `Copy ${label} command` : 'Copy command'}>
			{copied ? '✓ Copied' : 'Copy'}
		</button>
	</div>
</div>

<style>
	.cmd-row {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
		min-width: 0;
	}
	.cmd-key {
		font: var(--text-label-sm);
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	.cmd-val {
		display: flex;
		align-items: flex-start;
		gap: 0.4rem;
		padding: 0.4rem 0.5rem;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		background: var(--color-bg);
		min-width: 0;
	}
	.cmd-val code {
		flex: 1;
		min-width: 0;
		/* Long commands wrap rather than force a horizontal scrollbar onto the
		   dialog. `anywhere` with `word-break: normal` prefers the spaces
		   between arguments and only splits a token when one on its own is
		   wider than the box — `break-all` would hyphenate "http" in half. */
		word-break: normal;
		overflow-wrap: anywhere;
		white-space: pre-wrap;
		line-height: 1.45;
	}
	.mono {
		font: var(--text-code);
		font-size: 0.74rem;
	}
	.dense .cmd-val {
		padding: 0.3rem 0.45rem;
	}
	.dense .cmd-val code {
		font-size: 0.7rem;
	}
	.copy {
		background: none;
		border: none;
		font: inherit;
		font-size: 0.72rem;
		color: var(--color-primary, #6366f1);
		cursor: pointer;
		padding: 0.1rem 0.3rem;
		flex-shrink: 0;
		white-space: nowrap;
	}
	.copy:hover {
		text-decoration: underline;
	}
</style>
