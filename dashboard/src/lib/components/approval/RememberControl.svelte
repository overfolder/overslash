<script lang="ts">
	// The "Remember as" control that lives *in* the action bar.
	//
	// Picking a granularity here IS what "Allow & Remember" writes — the scope
	// ladder and the action bar's old read-only summary are now one thing, so the
	// operator never has to scroll to a side panel to change what gets stored.

	import type { SuggestedTier } from '$lib/session';
	import { splitKeys } from '$lib/approvals/format';
	import RiskBadge from './RiskBadge.svelte';

	let {
		tiers,
		selectedTier = $bindable(),
		useCustomKey = $bindable(),
		customKey = $bindable(),
		risk
	}: {
		tiers: SuggestedTier[];
		selectedTier: number;
		useCustomKey: boolean;
		customKey: string;
		risk: 'low' | 'med' | 'high';
	} = $props();

	let open = $state(false);
	let root: HTMLDivElement | undefined = $state();

	const currentLabel = $derived(
		useCustomKey ? 'Custom rule' : (tiers[selectedTier]?.description ?? 'No scope available')
	);
	// Every key the chosen tier would grant, not a "+N" that hides the recipient
	// the approval is really about — an action derives one key per recipient.
	const currentKeys = $derived(
		splitKeys(
			useCustomKey ? [customKey.trim() || 'service:action:arg'] : (tiers[selectedTier]?.keys ?? [])
		)
	);

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

<div class="aq-remember" bind:this={root}>
	<button
		type="button"
		class="aq-remember-trig"
		class:is-open={open}
		aria-expanded={open}
		onclick={() => (open = !open)}
	>
		<span class="aq-remember-lead">Remember as</span>
		<span class="aq-remember-cur">
			<span class="txt">{currentLabel}</span>
			<span class="caret">▾</span>
		</span>
		<span class="aq-remember-keys">
			{#each currentKeys.shown as k}<code>{k}</code>{/each}
			{#if currentKeys.hidden > 0}<span class="more">and {currentKeys.hidden} more</span>{/if}
		</span>
	</button>

	{#if open}
		<div class="aq-remember-pop" role="listbox" aria-label="Remember as a permission rule">
			<div class="aq-remember-pop-head">Remember as a permission rule</div>
			<div class="aq-scope">
				{#each tiers as tier, i}
					{@const split = splitKeys(tier.keys)}
					<button
						type="button"
						role="option"
						aria-selected={!useCustomKey && selectedTier === i}
						class="aq-scope-opt"
						class:is-sel={!useCustomKey && selectedTier === i}
						onclick={() => {
							selectedTier = i;
							useCustomKey = false;
							open = false;
						}}
					>
						<span class="aq-scope-radio"></span>
						<div class="aq-scope-main">
							<div class="aq-scope-label">
								<span class="txt">{tier.description}</span>
								<RiskBadge {risk} />
							</div>
							<div class="aq-scope-keys">
								{#each split.shown as k}<code class="aq-scope-key">{k}</code>{/each}
								{#if split.hidden > 0}<span class="more">and {split.hidden} more</span>{/if}
							</div>
						</div>
					</button>
				{/each}

				<div
					class="aq-scope-opt"
					class:is-sel={useCustomKey}
					role="option"
					aria-selected={useCustomKey}
					tabindex="0"
					onclick={() => (useCustomKey = true)}
					onkeydown={(e) => {
						// Only the option itself activates on Enter/Space — permission
						// keys legitimately contain spaces (`gmail:send:subject=Hi there`),
						// so keystrokes inside the field must reach the input untouched.
						if (e.target !== e.currentTarget) return;
						if (e.key === 'Enter' || e.key === ' ') {
							e.preventDefault();
							useCustomKey = true;
						}
					}}
				>
					<span class="aq-scope-radio"></span>
					<div class="aq-scope-main">
						<div class="aq-scope-label"><span class="txt">Custom… (advanced)</span></div>
						{#if useCustomKey}
							<!-- svelte-ignore a11y_autofocus -->
							<input
								class="aq-remember-input"
								placeholder="service:action:arg"
								spellcheck="false"
								autofocus
								bind:value={customKey}
								onclick={(e) => e.stopPropagation()}
							/>
						{:else}
							<div class="aq-scope-desc">Type a permission key by hand</div>
						{/if}
					</div>
				</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.aq-remember {
		position: relative;
		flex: 1;
		min-width: 0;
	}
	.aq-remember-trig {
		display: flex;
		flex-direction: column;
		gap: 2px;
		align-items: stretch;
		text-align: left;
		width: 100%;
		background: transparent;
		border: 0;
		padding: 5px 10px 6px;
		border-radius: 8px;
		cursor: pointer;
		min-width: 0;
		font: inherit;
		color: var(--color-text);
	}
	.aq-remember-trig:hover,
	.aq-remember-trig.is-open {
		background: var(--color-sidebar);
	}
	.aq-remember-lead {
		font-size: 12px;
		color: var(--color-text-secondary);
	}
	.aq-remember-cur {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 6px;
		width: 100%;
	}
	.aq-remember-cur .txt {
		font-size: 14px;
		font-weight: 600;
		color: var(--color-text-heading);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.aq-remember-cur .caret {
		color: var(--color-text-muted);
		font-size: 11px;
		flex: none;
	}
	.aq-remember-keys {
		display: flex;
		flex-direction: column;
		gap: 1px;
		min-width: 0;
	}
	.aq-remember-keys code {
		display: block;
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.aq-remember-pop {
		position: absolute;
		top: calc(100% + 8px);
		left: 0;
		z-index: 40;
		width: 100%;
		min-width: 320px;
		max-width: 88vw;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		box-shadow: var(--shadow-lg);
		padding: 12px;
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
		.aq-remember-pop {
			animation: none;
		}
	}
	.aq-remember-pop-head {
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--color-text-muted);
		margin: 2px 2px 10px;
	}

	.aq-scope {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.aq-scope-opt {
		display: flex;
		gap: 11px;
		padding: 11px 12px;
		border: 1px solid var(--color-border);
		border-radius: 10px;
		cursor: pointer;
		transition:
			border-color 0.1s,
			background 0.1s;
		align-items: flex-start;
		background: transparent;
		text-align: left;
		font: inherit;
		color: var(--color-text);
		width: 100%;
	}
	.aq-scope-opt:hover {
		background: var(--color-sidebar);
	}
	.aq-scope-opt.is-sel {
		border-color: var(--color-primary);
		background: var(--color-primary-bg);
	}
	.aq-scope-radio {
		width: 16px;
		height: 16px;
		border-radius: 50%;
		border: 1.5px solid var(--neutral-300);
		flex: none;
		margin-top: 1px;
		display: flex;
		align-items: center;
		justify-content: center;
		transition: border-color 0.1s;
	}
	.aq-scope-opt.is-sel .aq-scope-radio {
		border-color: var(--color-primary);
	}
	.aq-scope-opt.is-sel .aq-scope-radio::after {
		content: '';
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: var(--color-primary);
	}
	.aq-scope-main {
		flex: 1;
		min-width: 0;
	}
	.aq-scope-label {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
	}
	.aq-scope-label .txt {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text);
	}
	.aq-scope-opt.is-sel .aq-scope-label .txt {
		color: var(--color-primary);
	}
	.aq-scope-keys {
		display: flex;
		flex-direction: column;
		gap: 1px;
		margin-top: 3px;
	}
	.aq-scope-key {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-text-muted);
		white-space: normal;
		word-break: break-all;
	}
	.aq-scope-desc {
		font-size: 12px;
		color: var(--color-text-muted);
		margin-top: 4px;
	}
	.more {
		font-size: 11px;
		color: var(--color-text-muted);
	}
	.aq-remember-input {
		width: 100%;
		margin-top: 7px;
		height: 30px;
		border: 1px solid var(--color-border);
		border-radius: 7px;
		background: var(--color-bg);
		color: var(--color-text);
		font-family: var(--font-mono);
		font-size: 12px;
		padding: 0 8px;
		outline: 0;
	}
	.aq-remember-input:focus {
		border-color: var(--color-primary);
	}

	@media (max-width: 768px) {
		.aq-remember-pop {
			width: 100%;
			min-width: 0;
		}
	}
</style>
