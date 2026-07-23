<script lang="ts">
	// Expiry for the rule "Allow & Remember" writes — its own control next to
	// the Remember dropdown, not a select buried in a side panel.
	//
	// NOTE: the clock is an inline SVG (1.6px stroke). The Overslash unicode
	// glyph set has no clock, so this is a deliberate substitution.

	import { TTL_OPTIONS } from '$lib/approvals/format';

	let { value = $bindable() }: { value: string } = $props();

	let open = $state(false);
	let root: HTMLDivElement | undefined = $state();

	const label = $derived(TTL_OPTIONS.find((o) => o.value === value)?.label ?? 'Never');

	$effect(() => {
		if (!open) return;
		const onDown = (e: MouseEvent) => {
			if (root && !root.contains(e.target as Node)) open = false;
		};
		const onKey = (e: KeyboardEvent) => {
			if (e.key === 'Escape') open = false;
		};
		document.addEventListener('mousedown', onDown);
		document.addEventListener('keydown', onKey);
		return () => {
			document.removeEventListener('mousedown', onDown);
			document.removeEventListener('keydown', onKey);
		};
	});
</script>

<div class="aq-expctl" bind:this={root}>
	<button
		type="button"
		class="aq-expbtn"
		class:is-open={open}
		aria-expanded={open}
		aria-label="Rule expires: {label}"
		title="Rule expires"
		onclick={() => (open = !open)}
	>
		<svg
			class="aq-clock"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			stroke-width="1.6"
			stroke-linecap="round"
			stroke-linejoin="round"
			aria-hidden="true"
		>
			<circle cx="12" cy="12" r="8.5" />
			<path d="M12 7.5V12l3 1.8" />
		</svg>
		<span class="lbl">{label}</span>
		<span class="caret">▾</span>
	</button>

	{#if open}
		<div class="aq-expmenu" role="listbox" aria-label="Rule expiry">
			{#each TTL_OPTIONS as o}
				<button
					type="button"
					role="option"
					aria-selected={value === o.value}
					class="aq-expitem"
					class:is-sel={value === o.value}
					onclick={() => {
						value = o.value;
						open = false;
					}}>{o.label}</button
				>
			{/each}
		</div>
	{/if}
</div>

<style>
	.aq-expctl {
		position: relative;
		flex: none;
	}
	.aq-expbtn {
		display: inline-flex;
		align-items: center;
		gap: 7px;
		height: 40px;
		padding: 0 11px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		color: var(--color-text-secondary);
		font: var(--text-label);
		font-size: 13px;
		cursor: pointer;
		transition:
			background 0.1s,
			border-color 0.1s,
			color 0.1s;
	}
	.aq-expbtn:hover,
	.aq-expbtn.is-open {
		background: var(--color-sidebar);
		color: var(--color-text);
		border-color: var(--color-primary);
	}
	.aq-clock {
		width: 15px;
		height: 15px;
		flex: none;
		opacity: 0.85;
	}
	.aq-expbtn .lbl {
		white-space: nowrap;
	}
	.aq-expbtn .caret {
		font-size: 11px;
		color: var(--color-text-muted);
	}

	.aq-expmenu {
		position: absolute;
		top: calc(100% + 6px);
		right: 0;
		z-index: 40;
		min-width: 160px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		box-shadow: var(--shadow-lg);
		padding: 5px;
		animation: aqPop 0.12s ease both;
	}
	@keyframes aqPop {
		from {
			opacity: 0;
			transform: translateY(-4px);
		}
		to {
			opacity: 1;
			transform: none;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.aq-expmenu {
			animation: none;
		}
	}
	.aq-expitem {
		display: flex;
		width: 100%;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 8px 10px;
		border: 0;
		border-radius: 7px;
		background: transparent;
		color: var(--color-text);
		font: var(--text-label);
		font-size: 13px;
		text-align: left;
		cursor: pointer;
	}
	.aq-expitem:hover {
		background: var(--color-sidebar);
	}
	.aq-expitem.is-sel {
		color: var(--color-primary);
		font-weight: 600;
	}
	.aq-expitem.is-sel::after {
		content: '✓';
		font-size: 12px;
	}

	@media (max-width: 768px) {
		.aq-expbtn {
			width: 100%;
			justify-content: flex-start;
		}
		.aq-expmenu {
			left: 0;
			right: auto;
			width: 100%;
		}
	}
</style>
