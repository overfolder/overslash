<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import {
		getMcpStatus,
		getMcpLogs,
		wakeMcp,
		stopMcp,
		restartMcp,
		type McpStatusResponse,
		type McpLogLine
	} from '$lib/api/services';
	import { ApiError } from '$lib/session';

	let { serviceId }: { serviceId: string } = $props();

	let status = $state<McpStatusResponse | null>(null);
	let logs = $state<McpLogLine[]>([]);
	let error = $state<string | null>(null);
	let showLogs = $state(false);
	let busy = $state(false);
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	async function refresh(): Promise<void> {
		try {
			status = await getMcpStatus(serviceId);
			error = null;
		} catch (e) {
			if (e instanceof ApiError && e.status === 400) {
				// Not an MCP service — panel will render nothing.
				status = null;
				error = null;
			} else {
				error = e instanceof Error ? e.message : String(e);
			}
		}
	}

	async function refreshLogs(): Promise<void> {
		try {
			const r = await getMcpLogs(serviceId, 200);
			logs = r.lines;
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	}

	async function doAction(fn: () => Promise<unknown>): Promise<void> {
		busy = true;
		error = null;
		try {
			await fn();
			await refresh();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		refresh();
		pollTimer = setInterval(refresh, 5000);
	});

	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	const pillClass = $derived.by(() => {
		if (!status) return 'pill-unknown';
		switch (status.state) {
			case 'ready':
				return 'pill-ready';
			case 'starting':
				return 'pill-starting';
			case 'paused':
				return 'pill-paused';
			case 'stopped':
				return 'pill-stopped';
			case 'error':
				return 'pill-error';
			default:
				return 'pill-unknown';
		}
	});

	function fmtTs(iso: string | null): string {
		if (!iso) return '—';
		const d = new Date(iso);
		const secs = Math.round((Date.now() - d.getTime()) / 1000);
		if (secs < 60) return `${secs}s ago`;
		if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
		if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
		return d.toISOString().slice(0, 10);
	}
</script>

{#if status}
	<section class="panel">
		<header class="header">
			<h3>Runtime</h3>
			<span class="pill {pillClass}">{status.state}</span>
		</header>
		<dl class="meta">
			<dt>Package</dt>
			<dd>{status.package ?? '—'}@{status.version ?? '—'}</dd>
			<dt>PID</dt>
			<dd>{status.pid ?? '—'}</dd>
			<dt>Last used</dt>
			<dd title={status.last_used ?? ''}>{fmtTs(status.last_used)}</dd>
			<dt>Up since</dt>
			<dd title={status.since ?? ''}>{fmtTs(status.since)}</dd>
			{#if status.memory_mb !== null}
				<dt>Memory</dt>
				<dd>{status.memory_mb} MB</dd>
			{/if}
			{#if status.last_error}
				<dt>Last error</dt>
				<dd class="err">{status.last_error}</dd>
			{/if}
		</dl>

		<div class="controls">
			<button
				disabled={busy || status.state === 'ready' || status.state === 'starting'}
				onclick={() => doAction(() => wakeMcp(serviceId))}
			>
				Wake
			</button>
			<button
				disabled={busy || status.state === 'stopped'}
				onclick={() => doAction(() => stopMcp(serviceId))}
			>
				Stop
			</button>
			<button disabled={busy} onclick={() => doAction(() => restartMcp(serviceId))}>
				Restart
			</button>
			<button
				onclick={() => {
					showLogs = !showLogs;
					if (showLogs) refreshLogs();
				}}
			>
				{showLogs ? 'Hide logs' : 'Show logs'}
			</button>
		</div>

		{#if error}
			<div class="error">{error}</div>
		{/if}

		{#if showLogs}
			<div class="logs">
				{#if logs.length === 0}
					<p class="hint">No log lines yet.</p>
				{:else}
					{#each logs as line}
						<div class="line line-{line.level}">
							<span class="ts">{new Date(line.ts).toISOString().slice(11, 19)}</span>
							<span class="lvl">{line.level}</span>
							<span class="txt">{line.text}</span>
						</div>
					{/each}
				{/if}
				<button class="refresh" onclick={refreshLogs}>↻ Refresh logs</button>
			</div>
		{/if}
	</section>
{/if}

<style>
	.panel {
		background: var(--color-bg-elevated, #1a1a1a);
		border: 1px solid var(--color-border, #333);
		border-radius: 8px;
		padding: 1rem 1.2rem;
		margin-top: 1rem;
	}
	.header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.75rem;
	}
	.header h3 {
		margin: 0;
		font-size: 1rem;
	}
	.pill {
		padding: 0.15rem 0.6rem;
		border-radius: 999px;
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
	}
	.pill-ready {
		background: #164a2b;
		color: #7bf6a6;
	}
	.pill-starting {
		background: #123a5b;
		color: #86c8ff;
	}
	.pill-paused {
		background: #4b3a10;
		color: #ffd878;
	}
	.pill-stopped {
		background: #2a2a2a;
		color: #aaa;
	}
	.pill-error {
		background: #4a1a1a;
		color: #ff8a8a;
	}
	.pill-unknown {
		background: #2a2a2a;
		color: #888;
	}
	.meta {
		display: grid;
		grid-template-columns: 110px 1fr;
		row-gap: 0.3rem;
		column-gap: 0.8rem;
		margin: 0 0 0.75rem;
		font-size: 0.85rem;
	}
	.meta dt {
		color: var(--color-fg-muted, #888);
	}
	.meta dd {
		margin: 0;
	}
	.meta dd.err {
		color: #ff8a8a;
		white-space: pre-wrap;
	}
	.controls {
		display: flex;
		gap: 0.4rem;
		flex-wrap: wrap;
	}
	.controls button {
		padding: 0.35rem 0.75rem;
		border: 1px solid var(--color-border, #333);
		background: transparent;
		color: inherit;
		border-radius: 4px;
		font-size: 0.85rem;
		cursor: pointer;
	}
	.controls button:hover:not([disabled]) {
		background: var(--color-bg, #0d0d0d);
	}
	.controls button[disabled] {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.logs {
		margin-top: 0.75rem;
		max-height: 320px;
		overflow-y: auto;
		font-family: var(--font-mono, monospace);
		font-size: 0.78rem;
		background: #0a0a0a;
		border: 1px solid var(--color-border, #222);
		border-radius: 4px;
		padding: 0.5rem;
	}
	.line {
		display: grid;
		grid-template-columns: 70px 60px 1fr;
		gap: 0.4rem;
		padding: 0.08rem 0;
	}
	.line .ts {
		color: #666;
	}
	.line-stderr .lvl {
		color: #ff8a8a;
	}
	.line-stdio .lvl {
		color: #ffd878;
	}
	.line-event .lvl {
		color: #86c8ff;
	}
	.line .txt {
		white-space: pre-wrap;
		word-break: break-all;
	}
	.error {
		margin-top: 0.5rem;
		background: #3a1414;
		color: #fcc;
		border: 1px solid #6b2222;
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		font-size: 0.85rem;
	}
	.hint {
		color: var(--color-fg-muted);
	}
	.refresh {
		margin-top: 0.4rem;
		background: transparent;
		border: 1px solid #333;
		color: inherit;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.75rem;
	}
</style>
