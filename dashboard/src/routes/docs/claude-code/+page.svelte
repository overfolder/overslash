<script lang="ts">
	// Mirrors docs/agents/claude-code-setup.md — that file is the canonical
	// source. Update this page when the markdown changes; the two are
	// hand-mirrored (no build-time include yet) so a copy-pasteable snippet
	// is available next to the connection-creation surface.
	const settingsJson = `{
  "permissions": {
    "allow": [
      "mcp__overslash__overslash_search",
      "mcp__overslash__overslash_auth(action:whoami)",
      "mcp__overslash__overslash_auth(action:service_status)",
      "mcp__overslash__overslash_approve_downstream"
    ],
    "ask": [
      "mcp__overslash__overslash_call(service:overslash)",
      "mcp__overslash__overslash_approve_self"
    ]
  }
}`;

	let copied = $state(false);
	async function copySettings() {
		try {
			await navigator.clipboard.writeText(settingsJson);
			copied = true;
			setTimeout(() => (copied = false), 1800);
		} catch {
			// Clipboard API unavailable (older browser / insecure context).
			// The snippet is still selectable in the <pre> below — no fallback
			// implementation needed.
		}
	}
</script>

<svelte:head>
	<title>Claude Code setup · Overslash</title>
</svelte:head>

<div class="page">
	<header>
		<h1>Claude Code setup</h1>
		<p class="lede">
			Recommended <code>settings.json</code> rules for using Overslash from Claude Code.
			Drop these into your project's <code>.claude/settings.json</code> (or your
			user-level settings) so auto mode allow-lists discovery + downstream
			approvals and always asks before anything risky.
		</p>
	</header>

	<section>
		<div class="snippet-head">
			<h2>Recommended rules</h2>
			<button class="copy-btn" onclick={copySettings}>
				{copied ? 'Copied' : 'Copy'}
			</button>
		</div>
		<pre class="snippet"><code>{settingsJson}</code></pre>
	</section>

	<section>
		<h2>Why each rule is in the bucket it's in</h2>
		<dl>
			<dt><code>overslash_search</code></dt>
			<dd>Read-only discovery. Surfaces what's configured, nothing else. Auto-allow.</dd>
			<dt><code>overslash_auth(action:whoami) / (action:service_status)</code></dt>
			<dd>Identity introspection. Never mutates state. Auto-allow.</dd>
			<dt><code>overslash_approve_downstream</code></dt>
			<dd>
				Resolves an approval whose requester is a <em>proper descendant</em> of the
				caller — the delegation model working. The server-side classifier rejects
				this tool whenever the caller isn't actually an ancestor, so allow-listing
				it doesn't grant the agent extra authority.
			</dd>
			<dt><code>overslash_call(service:overslash)</code></dt>
			<dd>
				Wraps Overslash's own self-management surface (creating services, minting
				subagents, etc.). Always ask.
			</dd>
			<dt><code>overslash_approve_self</code></dt>
			<dd>
				Lets the agent rubber-stamp its own approvals. Only available once the
				operator flips <code>Allow self-approval</code> on the agent detail page.
				Always ask — this is the human-at-the-keyboard escape hatch, not a
				default.
			</dd>
		</dl>
	</section>

	<section>
		<h2>Picking the right approval tool</h2>
		<p>
			When <code>overslash_call</code> returns a <code>pending_approval</code>
			envelope it now carries a <code>relationship</code> field. Use it to pick
			the approval tool on the first try:
		</p>
		<table>
			<thead>
				<tr><th>relationship</th><th>Tool to call</th></tr>
			</thead>
			<tbody>
				<tr><td><code>"self"</code></td><td><code>overslash_approve_self</code></td></tr>
				<tr><td><code>"downstream"</code></td><td><code>overslash_approve_downstream</code></td></tr>
				<tr>
					<td><code>"not_in_your_chain"</code></td>
					<td>Don't try — bubble up; the server will reject either tool.</td>
				</tr>
			</tbody>
		</table>
		<p class="muted">
			Tool name is for Claude Code's permission rules; the actual allow/reject
			decision is server-side, comparing <code>caller.identity_id</code> against
			<code>approval.requester_identity_id</code>. A misroute returns a typed
			<code>not_in_your_chain</code> envelope and changes no state.
		</p>
	</section>
</div>

<style>
	.page {
		max-width: 760px;
		margin: 0 auto;
		padding: 32px 24px 64px;
		display: flex;
		flex-direction: column;
		gap: 32px;
	}
	header h1 {
		margin: 0 0 8px;
		font-size: 28px;
	}
	.lede {
		margin: 0;
		color: var(--text-muted, #666);
		line-height: 1.55;
	}
	section h2 {
		margin: 0 0 12px;
		font-size: 18px;
	}
	.snippet-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		margin-bottom: 8px;
	}
	.snippet-head h2 {
		margin: 0;
	}
	.copy-btn {
		padding: 6px 12px;
		font-size: 13px;
		border-radius: 6px;
		border: 1px solid var(--border, #ddd);
		background: var(--surface, #fff);
		cursor: pointer;
	}
	.copy-btn:hover {
		background: var(--surface-hover, #f5f5f5);
	}
	.snippet {
		margin: 0;
		padding: 16px;
		border-radius: 8px;
		background: var(--code-bg, #f6f8fa);
		border: 1px solid var(--border, #e1e4e8);
		overflow-x: auto;
		font-size: 13px;
		line-height: 1.5;
	}
	dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		column-gap: 16px;
		row-gap: 12px;
		margin: 0;
	}
	dt {
		font-family: ui-monospace, SFMono-Regular, monospace;
		font-size: 13px;
		white-space: nowrap;
	}
	dd {
		margin: 0;
		line-height: 1.55;
	}
	table {
		border-collapse: collapse;
		width: 100%;
		font-size: 14px;
	}
	th, td {
		text-align: left;
		padding: 8px 12px;
		border-bottom: 1px solid var(--border, #eee);
	}
	th {
		font-weight: 600;
	}
	code {
		font-family: ui-monospace, SFMono-Regular, monospace;
		font-size: 0.9em;
	}
	.muted {
		color: var(--text-muted, #666);
		font-size: 13px;
		line-height: 1.5;
	}
</style>
