<script lang="ts">
	// The scope control that lives *in* the action bar.
	//
	// Picking a granularity here IS what "Allow & Remember" writes — the scope
	// ladder and the action bar's old read-only summary are now one thing, so the
	// operator never has to scroll to a side panel to change what gets stored.
	//
	// Each option is exactly what it grants: the human description, then the
	// key(s) underneath. No radios, no repeated risk badge (every tier of one
	// approval carries the same risk) — the selected option is marked the same
	// way ExpiryControl marks its own.

	import type { SuggestedTier } from '$lib/session';
	import { splitKeys } from '$lib/approvals/format';

	let {
		tiers,
		selectedTier = $bindable(),
		useCustomKey = $bindable(),
		customKey = $bindable()
	}: {
		tiers: SuggestedTier[];
		selectedTier: number;
		useCustomKey: boolean;
		customKey: string;
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
		aria-label="Scope to remember: {currentLabel}"
		onclick={() => (open = !open)}
	>
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
		<div class="aq-remember-pop" role="listbox" aria-label="Scope to remember">
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
					<span class="aq-scope-label">{tier.description}</span>
					<span class="aq-scope-keys">
						{#each split.shown as k}<code>{k}</code>{/each}
						{#if split.hidden > 0}<span class="more">and {split.hidden} more</span>{/if}
					</span>
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
				<span class="aq-scope-label">Custom rule</span>
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
					<span class="aq-scope-keys"><span class="more">type a permission key by hand</span></span>
				{/if}
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
		padding: 5px;
		display: flex;
		flex-direction: column;
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

	/* One option = what it grants: description, then the key(s) it writes. */
	.aq-scope-opt {
		display: flex;
		flex-direction: column;
		gap: 3px;
		width: 100%;
		padding: 9px 11px;
		border: 0;
		border-radius: 8px;
		background: transparent;
		text-align: left;
		font: inherit;
		color: var(--color-text);
		cursor: pointer;
	}
	.aq-scope-opt:hover {
		background: var(--color-sidebar);
	}
	.aq-scope-opt.is-sel .aq-scope-label {
		color: var(--color-primary);
		font-weight: 600;
	}
	.aq-scope-opt.is-sel .aq-scope-label::after {
		content: '✓';
		margin-left: 7px;
		font-size: 12px;
	}
	.aq-scope-label {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text);
	}
	.aq-scope-keys {
		display: flex;
		flex-direction: column;
		gap: 1px;
		min-width: 0;
	}
	.aq-scope-keys code {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-text-muted);
		word-break: break-all;
	}
	.more {
		font-size: 11px;
		color: var(--color-text-muted);
	}
	.aq-remember-input {
		width: 100%;
		margin-top: 3px;
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
