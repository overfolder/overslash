<script lang="ts">
	import type { SecretSummary } from '$lib/types';

	let {
		value = $bindable<string>(''),
		available,
		loading = false,
		allowCreate = true,
		placeholder = 'my-api-key',
		id,
		disabled = false
	}: {
		value: string;
		available: SecretSummary[];
		loading?: boolean;
		allowCreate?: boolean;
		placeholder?: string;
		id?: string;
		disabled?: boolean;
	} = $props();

	let focused = $state(false);
	let highlight = $state(0);
	let inputEl: HTMLInputElement | undefined = $state();
	let wrapEl: HTMLDivElement | undefined = $state();

	$effect(() => {
		if (!focused) return;
		const onDoc = (e: MouseEvent) => {
			if (wrapEl && !wrapEl.contains(e.target as Node)) focused = false;
		};
		document.addEventListener('mousedown', onDoc);
		return () => document.removeEventListener('mousedown', onDoc);
	});

	$effect(() => {
		void value;
		void focused;
		highlight = 0;
	});

	const isExactMatch = $derived(
		value.length > 0 && available.some((s) => s.name === value)
	);

	const matches = $derived.by(() => {
		const q = value.trim().toLowerCase();
		if (!q) return available.slice(0, 8);
		return available.filter((s) => s.name.toLowerCase().includes(q)).slice(0, 8);
	});

	const isUnknownValue = $derived(value.length > 0 && !isExactMatch);

	// Hide the dropdown when the typed value already names a vault secret —
	// there's nothing to suggest and "No matches" would be both wrong and
	// confusing. Loading wins so the skeleton still appears on first open.
	const showDrop = $derived(focused && !disabled && (loading || !isExactMatch));

	function pick(name: string) {
		value = name;
		focused = false;
	}

	function clear() {
		value = '';
		inputEl?.focus();
	}

	function onKeyDown(e: KeyboardEvent) {
		if (disabled) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			focused = true;
			highlight = Math.min(highlight + 1, Math.max(matches.length - 1, 0));
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			highlight = Math.max(highlight - 1, 0);
		} else if (e.key === 'Enter') {
			if (matches.length === 0) return;
			e.preventDefault();
			pick(matches[highlight].name);
		} else if (e.key === 'Escape') {
			focused = false;
		}
	}
</script>

<div class="wrap" bind:this={wrapEl}>
	<div
		class="bar"
		class:disabled
		role="combobox"
		tabindex="-1"
		aria-expanded={focused}
		aria-haspopup="listbox"
		aria-controls={id ? `${id}-listbox` : undefined}
		onclick={() => inputEl?.focus()}
		onkeydown={(e) => {
			if (e.key === 'Enter' || e.key === ' ') inputEl?.focus();
		}}
	>
		<input
			{id}
			type="text"
			bind:this={inputEl}
			bind:value
			{disabled}
			onfocus={() => (focused = true)}
			onkeydown={onKeyDown}
			placeholder={placeholder}
			autocomplete="off"
			spellcheck="false"
		/>
		{#if isUnknownValue && !focused}
			<span class="new-tag" title="No secret with this name in the vault yet — create it on the Secrets page.">new</span>
		{/if}
		{#if value && !disabled}
			<button
				type="button"
				class="x"
				aria-label="Clear secret name"
				onclick={(e) => {
					e.stopPropagation();
					clear();
				}}>✕</button
			>
		{/if}
	</div>

	{#if showDrop}
		<div class="drop" id={id ? `${id}-listbox` : undefined} role="listbox">
			{#if loading}
				<div class="skeleton" aria-hidden="true"></div>
			{:else if matches.length > 0}
				{#each matches as s, i (s.name)}
					<button
						type="button"
						class="opt"
						class:active={i === highlight}
						onclick={() => pick(s.name)}
						onmouseenter={() => (highlight = i)}
					>
						<span class="mono">{s.name}</span>
						<span class="ver">v{s.current_version}</span>
					</button>
				{/each}
			{:else if available.length === 0 && value.trim() === ''}
				<div class="empty">
					No secrets in your vault yet — type a name to use one you'll create later.
				</div>
			{:else if isUnknownValue && allowCreate}
				<div class="empty">
					<span class="plus">+</span>
					<span>Will use new secret name <code class="mono">{value}</code> — create it on the Secrets page before this service runs.</span>
				</div>
			{:else}
				<div class="empty">No matches.</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.wrap {
		position: relative;
	}
	.bar {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 0.4rem 0.55rem;
		min-height: 36px;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-surface);
		cursor: text;
	}
	.bar:focus-within {
		border-color: var(--color-primary);
		outline: 2px solid var(--color-primary-bg);
		outline-offset: -1px;
	}
	.bar.disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.new-tag {
		font-size: 9px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--color-primary);
		font-weight: 600;
		opacity: 0.75;
	}
	input {
		flex: 1;
		min-width: 80px;
		border: 0;
		background: transparent;
		outline: 0;
		font: inherit;
		font-size: 0.9rem;
		font-family: var(--font-mono);
		color: var(--color-text);
	}
	.x {
		color: var(--color-text-muted);
		font-size: 11px;
		cursor: pointer;
		border: 0;
		background: transparent;
		padding: 0 4px;
	}
	.x:hover {
		color: var(--color-danger);
	}
	.drop {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		padding: 4px;
		z-index: 20;
		max-height: 260px;
		overflow: auto;
	}
	.opt {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.4rem 0.55rem;
		background: transparent;
		border: 0;
		border-radius: var(--radius-sm);
		cursor: pointer;
		text-align: left;
		color: var(--color-text);
		font: inherit;
	}
	.opt.active {
		background: var(--color-primary-bg);
		color: var(--color-primary);
	}
	.opt .mono {
		font-family: var(--font-mono);
		font-size: 0.85rem;
	}
	.ver {
		font-size: 0.7rem;
		color: var(--color-text-muted);
		font-family: var(--font-mono);
	}
	.empty {
		display: flex;
		gap: 6px;
		align-items: baseline;
		padding: 0.5rem 0.6rem;
		font-size: 0.78rem;
		color: var(--color-text-muted);
	}
	.empty .plus {
		color: var(--color-primary);
		font-weight: 600;
	}
	.empty code {
		background: var(--color-primary-bg);
		padding: 1px 5px;
		border-radius: var(--radius-sm);
		font-size: 0.75rem;
		font-family: var(--font-mono);
	}
	.skeleton {
		height: 28px;
		margin: 4px;
		border-radius: var(--radius-sm);
		background: var(--color-border-subtle);
		opacity: 0.6;
	}
</style>
