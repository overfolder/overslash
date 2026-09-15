<!--
	The verdict from a credential probe, rendered the same way everywhere it
	appears: the create wizard, the service detail page, and the public setup
	page.

	Deliberately never blocking. A probe answers "do these credentials work",
	and a template can be right while an upstream is merely down — so a failed
	verdict offers a retry and says what happened, and the caller decides
	whether that matters.
-->
<script lang="ts">
	import type { ServiceTestResponse } from '$lib/types';

	let {
		result,
		running = false,
		onRetry
	}: {
		result: ServiceTestResponse | null;
		running?: boolean;
		onRetry?: () => void;
	} = $props();

	const tone = $derived.by(() => {
		if (running || !result) return 'pending';
		switch (result.status) {
			case 'ok':
				return 'ok';
			case 'pending_approval':
			case 'needs_authentication':
			case 'not_supported':
				return 'warn';
			default:
				return 'fail';
		}
	});

	const headline = $derived.by(() => {
		if (running) return 'Testing…';
		if (!result) return '';
		switch (result.status) {
			case 'ok':
				return result.latency_ms != null
					? `Works — responded in ${result.latency_ms} ms`
					: 'Works';
			case 'pending_approval':
				return 'Waiting on an approval';
			case 'needs_authentication':
				return 'No usable credential yet';
			case 'not_supported':
				return 'This service has no test action';
			default:
				return result.http_status
					? `Test failed (HTTP ${result.http_status})`
					: 'Test failed';
		}
	});

	const detail = $derived.by(() => {
		if (!result || running) return null;
		switch (result.status) {
			case 'pending_approval':
				return 'The call needs someone to approve it before it can run.';
			case 'needs_authentication':
				return 'Provide a credential, then test again.';
			case 'not_supported':
				return 'Its template names no read action to probe with, so there is nothing to run.';
			default:
				return result.error ?? null;
		}
	});

	// A retry only makes sense for an outcome that could come out differently.
	const canRetry = $derived(
		!running && !!onRetry && !!result && result.status !== 'not_supported'
	);
</script>

{#if running || result}
	<div class="verdict {tone}" role="status" aria-live="polite">
		<div class="line">
			<span class="dot" aria-hidden="true"></span>
			<span class="headline">{headline}</span>
			{#if canRetry}
				<button type="button" class="retry" onclick={onRetry}>Retry</button>
			{/if}
		</div>
		{#if detail}
			<p class="detail">{detail}</p>
		{/if}
		{#if result?.status === 'pending_approval' && result.approval_url}
			<a class="link" href={result.approval_url}>Open the approval</a>
		{/if}
		{#if result?.action && result.status !== 'not_supported'}
			<p class="ran">
				Ran <code>{result.action}</code>{#if result.summary} — {result.summary}{/if}
			</p>
		{/if}
	</div>
{/if}

<style>
	.verdict {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.7rem 0.85rem;
		font-size: 0.85rem;
		line-height: 1.45;
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.line {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.headline {
		font-weight: 600;
		color: var(--color-text);
	}
	.dot {
		width: 0.55rem;
		height: 0.55rem;
		border-radius: 999px;
		flex: none;
		background: var(--color-text-muted);
	}
	.ok {
		background: rgba(34, 197, 94, 0.08);
		border-color: rgba(34, 197, 94, 0.3);
	}
	.ok .dot {
		background: #15803d;
	}
	.warn {
		background: rgba(234, 179, 8, 0.1);
		border-color: rgba(234, 179, 8, 0.35);
	}
	.warn .dot {
		background: #a16207;
	}
	.fail {
		background: rgba(220, 38, 38, 0.08);
		border-color: rgba(220, 38, 38, 0.3);
	}
	.fail .dot {
		background: #b91c1c;
	}
	.pending .dot {
		animation: pulse 1s ease-in-out infinite;
	}
	@keyframes pulse {
		50% {
			opacity: 0.25;
		}
	}
	/* Respect a reduced-motion preference: the dot still reads as "busy" from
	   its position in the line and the "Testing…" headline beside it. */
	@media (prefers-reduced-motion: reduce) {
		.pending .dot {
			animation: none;
		}
	}
	.detail {
		margin: 0;
		color: var(--color-text-muted);
		overflow-wrap: anywhere;
	}
	.ran {
		margin: 0;
		font-size: 0.78rem;
		color: var(--color-text-muted);
	}
	.ran code {
		font-family: var(--font-mono);
	}
	.retry {
		margin-left: auto;
		padding: 0.2rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
		color: var(--color-text);
		font: inherit;
		font-size: 0.78rem;
		cursor: pointer;
	}
	.retry:hover {
		background: var(--color-bg);
	}
	.link {
		color: var(--color-primary);
		font-weight: 600;
	}
</style>
