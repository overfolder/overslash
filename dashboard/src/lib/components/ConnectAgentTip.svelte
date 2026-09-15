<script lang="ts">
	// "How do I get an agent in here?" — the commands, with this org's real MCP
	// URL already substituted.
	//
	// Pointing a client at `<slug>.api.overslash.com/mcp` is not just a
	// convenience: per D26 the subdomain is an enforced enrollment lock, so the
	// agent the client enrolls is guaranteed to land in this org. That is why
	// the URL is rendered live from the session rather than documented with a
	// `<your-org>` placeholder.
	//
	// `mcpUrl` is whatever `ownMcpUrlFor` decided — the slug form on the
	// managed cloud, the dashboard's own origin anywhere else. This component
	// just renders it; the choice lives in `$lib/env`.
	import CopyCommand from './CopyCommand.svelte';

	let { mcpUrl, variant = 'panel' }: { mcpUrl: string; variant?: 'panel' | 'modal' } = $props();

	const claudeCmd = $derived(
		`claude mcp add --transport http --scope user overslash ${mcpUrl}`
	);
	const genericCmd = $derived(`npx -y mcp-remote ${mcpUrl}`);
</script>

<div class="tip" class:modal={variant === 'modal'}>
	<p class="tip-lede">
		Point an MCP client at your org and it enrolls its own agent — no need to create
		one here first.
	</p>
	<CopyCommand label="Claude Code" command={claudeCmd} dense={variant === 'modal'} />
	<CopyCommand label="Any MCP client" command={genericCmd} dense={variant === 'modal'} />
	<p class="tip-note">
		A browser window opens once so you can sign in and name the agent.
	</p>
	<a class="tip-link" href="/docs/claude-code">Recommended Claude Code rules →</a>
</div>

<style>
	.tip {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
		text-align: left;
		min-width: 0;
	}
	.tip-lede {
		margin: 0;
		font-size: 0.82rem;
		line-height: 1.5;
		color: var(--color-text-muted);
	}
	.tip-note {
		margin: 0;
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.tip-link {
		/* Block-level in a column flexbox would stretch the hover/focus target
		   across the whole card; keep it the width of its own text. */
		align-self: flex-start;
		font-size: 0.74rem;
		color: var(--color-primary, #6366f1);
		text-decoration: none;
	}
	.tip-link:hover {
		text-decoration: underline;
	}
	.modal {
		gap: 0.5rem;
	}
	.modal .tip-lede {
		font-size: 0.78rem;
	}
</style>
