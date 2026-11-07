<script lang="ts">
	/**
	 * Time window for the audit log: one-click presets plus a custom range.
	 *
	 * Holds no range of its own — it renders `value` and reports a new one
	 * through `onchange`, so the URL stays the single source of truth. The
	 * custom popover keeps a draft until Apply, so half-typed dates never
	 * trigger a fetch.
	 */
	import {
		RANGE_PRESETS,
		fromLocalInput,
		rangeLabel,
		resolveRange,
		toLocalInput,
		type TimeRange
	} from './timeRange';

	let {
		value,
		onchange
	}: {
		value: TimeRange;
		onchange: (next: TimeRange) => void;
	} = $props();

	let open = $state(false);
	let draftSince = $state('');
	let draftUntil = $state('');
	let wrapEl: HTMLDivElement | undefined = $state();

	const draftError = $derived.by(() => {
		const since = fromLocalInput(draftSince);
		const until = fromLocalInput(draftUntil);
		if (!since || !until) return 'Pick both a start and an end.';
		if (since >= until) return 'The start must be before the end.';
		return null;
	});

	function openCustom() {
		// Seed the draft with whatever window is showing now, so tweaking
		// "last 24h" into a custom range starts from it rather than from blank.
		const r = resolveRange(value);
		draftSince = r.since ? toLocalInput(r.since) : '';
		draftUntil = toLocalInput(r.until);
		open = !open;
	}

	function apply() {
		const since = fromLocalInput(draftSince);
		const until = fromLocalInput(draftUntil);
		if (!since || !until || draftError) return;
		open = false;
		onchange({ kind: 'absolute', since, until });
	}

	$effect(() => {
		if (!open) return;
		const onDoc = (e: MouseEvent) => {
			if (wrapEl && !wrapEl.contains(e.target as Node)) open = false;
		};
		const onKey = (e: KeyboardEvent) => {
			if (e.key === 'Escape') open = false;
		};
		document.addEventListener('mousedown', onDoc);
		document.addEventListener('keydown', onKey);
		return () => {
			document.removeEventListener('mousedown', onDoc);
			document.removeEventListener('keydown', onKey);
		};
	});
</script>

<div class="picker" bind:this={wrapEl} data-test="audit-time-range">
	<div class="segments" role="group" aria-label="Time range">
		{#each RANGE_PRESETS as preset (preset)}
			{@const active = value.kind === 'relative' && value.preset === preset}
			<button
				type="button"
				class="seg"
				class:active
				aria-pressed={active}
				title={`Show the ${rangeLabel({ kind: 'relative', preset })}`}
				onclick={() => onchange({ kind: 'relative', preset })}
			>
				{preset}
			</button>
		{/each}
		<button
			type="button"
			class="seg custom"
			class:active={value.kind !== 'relative'}
			aria-pressed={value.kind !== 'relative'}
			aria-expanded={open}
			aria-haspopup="dialog"
			onclick={openCustom}
		>
			{value.kind === 'relative' ? 'Custom' : rangeLabel(value)}
			<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
				<path d="m6 9 6 6 6-6" fill="none" stroke="currentColor" stroke-width="1.5" />
			</svg>
		</button>
	</div>

	{#if open}
		<div class="pop" role="dialog" aria-label="Custom time range">
			<label>
				<span>From</span>
				<input type="datetime-local" bind:value={draftSince} data-test="range-since" />
			</label>
			<label>
				<span>To</span>
				<input type="datetime-local" bind:value={draftUntil} data-test="range-until" />
			</label>
			<p class="hint">Local time · {Intl.DateTimeFormat().resolvedOptions().timeZone}</p>
			{#if draftError}
				<p class="error">{draftError}</p>
			{/if}
			<div class="pop-actions">
				<button type="button" onclick={() => (open = false)}>Cancel</button>
				<button type="button" class="primary" onclick={apply} disabled={!!draftError}>
					Apply
				</button>
			</div>
		</div>
	{/if}
</div>

<style>
	.picker {
		position: relative;
		flex: none;
	}
	.segments {
		display: inline-flex;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		overflow: hidden;
		background: var(--color-bg);
	}
	.seg {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 6px 12px;
		border: none;
		border-left: 1px solid var(--color-border);
		background: transparent;
		color: var(--color-text-secondary, var(--color-text));
		font: inherit;
		font-size: 0.85rem;
		cursor: pointer;
		white-space: nowrap;
	}
	.seg:first-child {
		border-left: none;
	}
	.seg:hover:not(.active) {
		background: var(--color-surface);
		color: var(--color-text);
	}
	.seg.active {
		background: var(--color-primary-bg);
		color: var(--color-primary);
		font-weight: 600;
	}
	.pop {
		position: absolute;
		top: calc(100% + 6px);
		right: 0;
		z-index: 20;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		width: 280px;
		padding: var(--space-4);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md, 8px);
		background: var(--color-bg);
		box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
	}
	.pop label {
		display: flex;
		flex-direction: column;
		gap: 4px;
		font-size: var(--text-label, 0.75rem);
		color: var(--color-text-muted);
	}
	.pop input {
		padding: 6px 8px;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		background: var(--color-bg);
		color: var(--color-text);
		font: inherit;
	}
	.hint,
	.error {
		margin: 0;
		font-size: var(--text-label, 0.75rem);
	}
	.hint {
		color: var(--color-text-muted);
	}
	.error {
		color: var(--color-danger);
	}
	.pop-actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
	}
	.pop-actions button {
		padding: 6px 12px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		border-radius: var(--radius-sm, 4px);
		cursor: pointer;
	}
	.pop-actions .primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	.pop-actions button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
