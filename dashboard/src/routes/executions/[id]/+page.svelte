<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import type { ExecutionDetail } from '$lib/session';
	import { getExecution, cancelExecution } from '$lib/api/executions';
	import { onEvent, EXECUTION_EVENT_TYPES } from '$lib/stores/events.svelte';
	import { formatTime } from '$lib/utils/time';

	const id = $derived($page.params.id ?? '');

	let detail = $state<ExecutionDetail | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let cancelling = $state(false);

	async function load() {
		try {
			detail = await getExecution(id);
			error = null;
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				error = 'Execution not found.';
			} else if (e instanceof ApiError && e.status === 403) {
				error = 'You are not authorized to view this execution.';
			} else {
				error = e instanceof ApiError ? e.message : 'Failed to load execution';
			}
		} finally {
			loading = false;
		}
	}

	onMount(load);

	$effect(() =>
		onEvent([...EXECUTION_EVENT_TYPES, 'stream.resync'], (e) => {
			// The payload carries no body, so treat it purely as a cue to refetch.
			const target = (e.data as { execution_id?: string } | undefined)?.execution_id;
			if (!target || target === id) void load();
		})
	);

	const terminal = $derived(
		detail ? ['executed', 'failed', 'cancelled', 'expired'].includes(detail.status) : false
	);

	async function doCancel() {
		if (!detail) return;
		cancelling = true;
		try {
			detail = await cancelExecution(id);
			error = null;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Cancel failed';
		} finally {
			cancelling = false;
		}
	}

	function pretty(v: unknown): string {
		try {
			return JSON.stringify(v, null, 2);
		} catch {
			return String(v);
		}
	}
</script>

<div class="page">
	<a class="back" href="/executions">← Executions</a>

	{#if loading}
		<div class="empty">Loading…</div>
	{:else if error && !detail}
		<div class="error">{error}</div>
	{:else if detail}
		<header class="page-head">
			<div>
				<h1>{detail.service ?? 'Execution'}</h1>
				<p class="sub mono">{detail.id}</p>
			</div>
			{#if !terminal}
				<button type="button" class="btn" onclick={doCancel} disabled={cancelling}>
					{cancelling ? 'Cancelling…' : 'Cancel'}
				</button>
			{/if}
		</header>

		{#if error}
			<div class="error">{error}</div>
		{/if}

		<div class="card meta">
			<dl>
				<div><dt>Status</dt><dd>{detail.status}</dd></div>
				<div>
					<dt>Origin</dt>
					<dd>
						{#if detail.origin === 'approval' && detail.approval_id}
							<!-- Round-tripping matters: a gated async call is visible from both
							     sides, and the approval is where the reviewer's context lives. -->
							<a href="/approvals/{detail.approval_id}">Approved call</a>
						{:else if detail.origin === 'approval'}
							Approved call
						{:else}
							Direct async call
						{/if}
					</dd>
				</div>
				<div><dt>Created</dt><dd>{formatTime(detail.created_at)}</dd></div>
				<div><dt>Started</dt><dd>{detail.started_at ? formatTime(detail.started_at) : '—'}</dd></div>
				<div><dt>Completed</dt><dd>{detail.completed_at ? formatTime(detail.completed_at) : '—'}</dd></div>
				{#if detail.http_status_code}
					<div><dt>Upstream</dt><dd>{detail.http_status_code}</dd></div>
				{/if}
				{#if detail.attempts}
					<div>
						<dt>Attempts</dt>
						<dd title="Attempts that lost a worker lease — usually a scale-in mid-job.">
							{detail.attempts}
						</dd>
					</div>
				{/if}
			</dl>
		</div>

		{#if detail.cancel_requested && detail.status === 'executing'}
			<p class="note">
				Cancellation requested. The worker stops on its next heartbeat — this stops Overslash
				waiting, it does not recall a request the upstream has already received.
			</p>
		{/if}

		{#if detail.result_redacted}
			<div class="card hidden-body">
				<h2>Result hidden</h2>
				<p>
					You can see that this call ran, but not what it returned — you are not the requesting
					agent, not in its chain, and not an org admin.
				</p>
			</div>
		{:else if detail.error}
			<div class="card">
				<h2>Error</h2>
				<pre>{detail.error}</pre>
			</div>
		{:else if detail.result !== undefined && detail.result !== null}
			<div class="card">
				<h2>Result</h2>
				<pre>{pretty(detail.result)}</pre>
			</div>
		{:else if !terminal}
			<div class="empty">Still running — this page updates itself when it finishes.</div>
		{/if}
	{/if}
</div>

<style>
	.page {
		max-width: 900px;
	}
	.back {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		text-decoration: none;
		display: inline-block;
		margin-bottom: 12px;
	}
	.back:hover {
		color: var(--color-text);
	}
	.page-head {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 20px;
	}
	h1 {
		font: var(--text-h1);
		margin: 0;
		color: var(--color-text-heading);
	}
	h2 {
		font-size: 13px;
		margin: 0 0 8px;
		color: var(--color-text-heading);
	}
	.sub {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		margin: 4px 0 0;
	}
	.mono {
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 12px;
	}
	.btn {
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		border-radius: 6px;
		cursor: pointer;
		font: var(--text-label);
		padding: 8px 14px;
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: default;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 16px;
		margin-bottom: 16px;
	}
	.meta dl {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 12px 24px;
		margin: 0;
	}
	dt {
		font-size: 11px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--color-text-muted);
		margin-bottom: 2px;
	}
	dd {
		margin: 0;
		font: var(--text-body);
	}
	pre {
		margin: 0;
		overflow-x: auto;
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 12px;
		white-space: pre-wrap;
		word-break: break-word;
	}
	.hidden-body {
		border-style: dashed;
		color: var(--color-text-muted);
	}
	.hidden-body p {
		margin: 0;
		font-size: 13px;
		max-width: 60ch;
	}
	.note {
		font-size: 13px;
		color: var(--color-text-muted);
		margin: 0 0 16px;
		max-width: 66ch;
	}
	.error {
		background: rgba(229, 56, 54, 0.06);
		border: 1px solid rgba(229, 56, 54, 0.2);
		color: var(--color-danger);
		border-radius: 8px;
		padding: 10px 12px;
		margin-bottom: 16px;
		font-size: 13px;
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 32px 24px;
		text-align: center;
		color: var(--color-text-muted);
		font-size: 13px;
	}
</style>
