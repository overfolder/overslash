<script lang="ts">
	import { highlightJson } from '$lib/api';
	import type { ExecuteResponse } from '$lib/types';

	let {
		response,
		error,
		running,
		elapsedMs
	}: {
		response: ExecuteResponse | null;
		error: string | null;
		running: boolean;
		elapsedMs: number | null;
	} = $props();

	function statusVariant(code: number): 'ok' | 'warn' | 'err' {
		if (code >= 200 && code < 300) return 'ok';
		if (code >= 300 && code < 500) return 'warn';
		return 'err';
	}

	function prettyBody(raw: string): string {
		const trimmed = raw.trim();
		if (!trimmed) return '<span class="muted">(empty body)</span>';
		try {
			return highlightJson(JSON.parse(trimmed));
		} catch {
			// Not JSON — render as plain text.
			return escapeText(trimmed);
		}
	}

	function escapeText(s: string): string {
		return s
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;');
	}
</script>

<section class="card" aria-label="Response">
	<header class="head">
		<h2>Response</h2>
		{#if response && response.status === 'executed'}
			{@const v = statusVariant(response.result.status_code)}
			<span class={`chip ${v}`}>{response.result.status_code}</span>
			<span class="duration">{response.result.duration_ms}ms</span>
		{:else if elapsedMs !== null && !running}
			<span class="duration">{Math.round(elapsedMs)}ms</span>
		{/if}
	</header>

	{#if running}
		<p class="placeholder">Executing…</p>
	{:else if error}
		<div class="error">
			<strong>Request failed</strong>
			<p>{error}</p>
		</div>
	{:else if !response}
		<p class="placeholder">Run a request to see the response here.</p>
	{:else if response.status === 'executed'}
		<pre class="code">{@html prettyBody(response.result.body)}</pre>
	{:else if response.status === 'pending_approval'}
		<div class="info">
			<strong>Pending approval</strong>
			<p>{response.action_description}</p>
			<a class="btn" href={`/approvals/${response.approval_id}`}>Open approval →</a>
			<p class="muted">Expires {new Date(response.expires_at).toLocaleString()}</p>
		</div>
	{:else if response.status === 'denied'}
		<div class="error">
			<strong>Denied</strong>
			<p>{response.reason}</p>
		</div>
	{/if}
</section>

<style>
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: 1.25rem;
	}
	.head {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.9rem;
	}
	h2 {
		font: var(--text-h3);
		margin: 0;
		color: var(--color-text-heading);
	}
	.chip {
		padding: 0.1rem 0.55rem;
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 0.72rem;
		font-weight: 600;
	}
	.chip.ok {
		background: var(--badge-bg-success);
		color: var(--success-500);
	}
	.chip.warn {
		background: var(--badge-bg-warning);
		color: var(--warning-500);
	}
	.chip.err {
		background: var(--badge-bg-danger);
		color: var(--error-500);
	}
	.duration {
		font-size: 0.78rem;
		color: var(--color-text-muted);
	}
	.code {
		margin: 0;
		padding: 0.9rem 1rem;
		background: var(--color-bg);
		border: 1px solid var(--color-border-subtle);
		border-radius: var(--radius-md);
		font-family: var(--font-mono);
		font-size: 0.82rem;
		color: var(--color-text);
		overflow: auto;
		max-height: 520px;
		white-space: pre;
	}
	:global(.json-key) { color: var(--primary-600); }
	:global(.json-string) { color: var(--success-500); }
	:global(.json-number) { color: var(--orange-500); }
	:global(.json-bool) { color: var(--primary-600); }
	:global(.json-null) { color: var(--color-text-muted); }
	:global(.json-bracket) { color: var(--color-text-muted); }
	.placeholder {
		color: var(--color-text-muted);
		font-size: 0.88rem;
		margin: 0;
	}
	.error,
	.info {
		padding: 0.9rem 1rem;
		border-radius: var(--radius-md);
		font-size: 0.88rem;
	}
	.error {
		background: var(--badge-bg-danger);
		color: var(--error-500);
		border: 1px solid rgba(229, 56, 54, 0.25);
	}
	.info {
		background: var(--badge-bg-warning);
		color: var(--warning-500);
		border: 1px solid rgba(235, 176, 31, 0.25);
	}
	.error strong,
	.info strong {
		display: block;
		margin-bottom: 0.25rem;
		font-weight: 600;
	}
	.error p,
	.info p {
		margin: 0.25rem 0;
		color: inherit;
	}
	.btn {
		display: inline-block;
		margin-top: 0.4rem;
		padding: 0.35rem 0.75rem;
		background: var(--color-primary);
		color: #fff;
		border-radius: var(--radius-md);
		text-decoration: none;
		font-size: 0.82rem;
		font-weight: 500;
	}
	.muted {
		color: var(--color-text-muted);
		font-size: 0.78rem;
	}
</style>
