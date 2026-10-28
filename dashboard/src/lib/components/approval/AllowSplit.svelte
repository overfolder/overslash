<script lang="ts">
	// The single Allow control: a split button whose caret picks the duration
	// and whose main half runs it. "Once" is a plain allow; every other choice
	// is "Allow & Remember" at the scope RememberControl holds, with that
	// duration as the rule's expiry — so once-vs-remember and the expiry are one
	// decision instead of two buttons plus a clock menu.

	import { TTL_OPTIONS } from '#lib/approvals/format.ts';

	let {
		dur = $bindable('once'),
		disabled = false,
		canRemember = true,
		onallow
	}: {
		dur?: string;
		disabled?: boolean;
		canRemember?: boolean;
		onallow: (dur: string) => void;
	} = $props();

	// `forever` sits last as "Always"; the rest read "For <ttl>".
	const DURS = [
		{ value: 'once', label: 'Once', btn: 'once' },
		...TTL_OPTIONS.filter((o) => o.value !== 'forever').map((o) => ({
			value: o.value as string,
			label: `For ${o.label}`,
			btn: `for ${o.label}`
		})),
		{ value: 'forever', label: 'Always', btn: 'always' }
	];

	let open = $state(false);
	let root: HTMLDivElement | undefined = $state();

	const current = $derived(DURS.find((d) => d.value === dur) ?? DURS[0]);
	const mainDisabled = $derived(disabled || (dur !== 'once' && !canRemember));

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

<div class="aq-split" bind:this={root}>
	<button
		type="button"
		class="aq-split-main"
		disabled={mainDisabled}
		onclick={() => onallow(current.value)}>Allow {current.btn}</button
	>
	<button
		type="button"
		class="aq-split-tog"
		aria-label="More allow options"
		aria-haspopup="menu"
		aria-expanded={open}
		{disabled}
		onclick={() => (open = !open)}>▾</button
	>

	{#if open}
		<div class="aq-allowmenu" role="menu" aria-label="Allow duration">
			{#each DURS as d, i}
				{#if i === 1}<div class="aq-allowmenu-sep">Allow &amp; remember</div>{/if}
				<button
					type="button"
					role="menuitemradio"
					aria-checked={d.value === dur}
					class="aq-allowitem"
					class:is-sel={d.value === dur}
					disabled={d.value !== 'once' && !canRemember}
					onclick={() => {
						dur = d.value;
						open = false;
					}}
				>
					<span>{d.label}</span>
					{#if d.value === dur}<span class="chk">✓</span>{/if}
				</button>
			{/each}
		</div>
	{/if}
</div>

<style>
	.aq-split {
		position: relative;
		display: inline-flex;
		align-items: stretch;
	}
	.aq-split-main,
	.aq-split-tog {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: var(--color-primary);
		color: #fff;
		border: 1px solid var(--color-primary);
		font-family: inherit;
		font-size: 14px;
		font-weight: 500;
		cursor: pointer;
		transition:
			background 0.1s,
			border-color 0.1s;
	}
	.aq-split-main {
		padding: 10px 16px;
		border-radius: 8px 0 0 8px;
		white-space: nowrap;
	}
	.aq-split-tog {
		padding: 10px 11px;
		border-radius: 0 8px 8px 0;
		border-left-color: rgba(255, 255, 255, 0.28);
		font-size: 12px;
	}
	.aq-split-main:not(:disabled):hover,
	.aq-split-tog:not(:disabled):hover {
		background: var(--color-primary-hover);
		border-color: var(--color-primary-hover);
	}
	.aq-split-tog:not(:disabled):hover {
		border-left-color: rgba(255, 255, 255, 0.28);
	}
	.aq-split-main:disabled,
	.aq-split-tog:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}

	.aq-allowmenu {
		position: absolute;
		top: calc(100% + 6px);
		right: 0;
		z-index: 40;
		min-width: 220px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		box-shadow: var(--shadow-lg);
		padding: 6px;
		display: flex;
		flex-direction: column;
		gap: 1px;
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
		.aq-allowmenu {
			animation: none;
		}
	}
	.aq-allowmenu-sep {
		border-top: 1px solid var(--color-border-subtle);
		margin: 4px 0 0;
		padding: 8px 8px 4px;
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--color-text-muted);
	}
	.aq-allowitem {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		text-align: left;
		background: transparent;
		border: 0;
		border-radius: 6px;
		padding: 8px 10px;
		font: var(--text-body);
		color: var(--color-text);
		cursor: pointer;
		transition: background 0.1s;
	}
	.aq-allowitem:not(:disabled):hover {
		background: var(--color-sidebar);
	}
	.aq-allowitem:disabled {
		opacity: 0.45;
		cursor: not-allowed;
	}
	.aq-allowitem.is-sel {
		color: var(--color-primary);
		font-weight: 500;
	}
	.aq-allowitem .chk {
		color: var(--color-primary);
		font-size: 12px;
	}

	@media (max-width: 768px) {
		.aq-split {
			flex: 1;
		}
		.aq-split-main {
			flex: 1;
		}
		.aq-allowmenu {
			left: 0;
			right: 0;
			min-width: 0;
		}
	}
</style>
