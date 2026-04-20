<script lang="ts">
	interface GroupOption {
		id?: string;
		name: string;
		member_count?: number;
	}

	let {
		available = [],
		value = $bindable<string[]>([]),
		allowCreate = true,
		placeholder = 'Search groups…'
	}: {
		available?: GroupOption[];
		value: string[];
		allowCreate?: boolean;
		placeholder?: string;
	} = $props();

	let query = $state('');
	let focused = $state(false);
	let highlight = $state(0);
	let inputEl: HTMLInputElement | undefined = $state();
	let barEl: HTMLDivElement | undefined = $state();

	const slugRe = /^[a-z0-9-]+$/;

	$effect(() => {
		if (!focused) return;
		const onDoc = (e: MouseEvent) => {
			if (barEl && !barEl.contains(e.target as Node)) focused = false;
		};
		document.addEventListener('mousedown', onDoc);
		return () => document.removeEventListener('mousedown', onDoc);
	});

	// Reset the highlighted row when the pool of visible matches changes.
	$effect(() => {
		void query;
		void focused;
		highlight = 0;
	});

	const matches = $derived.by(() => {
		const q = query.trim().toLowerCase();
		const unselected = available.filter((g) => !value.includes(g.name));
		if (!q) return unselected.slice(0, 8);
		return unselected.filter((g) => g.name.includes(q)).slice(0, 8);
	});

	const canCreate = $derived.by(() => {
		const q = query.trim().toLowerCase();
		const exact = available.some((g) => g.name === q) || value.includes(q);
		return allowCreate && q.length > 0 && !exact && slugRe.test(q);
	});

	const totalOptions = $derived(matches.length + (canCreate ? 1 : 0));

	function add(name: string) {
		if (!value.includes(name)) value = [...value, name];
		query = '';
		inputEl?.focus();
	}
	function remove(name: string) {
		value = value.filter((g) => g !== name);
	}

	function onKeyDown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			highlight = Math.min(highlight + 1, totalOptions - 1);
			focused = true;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			highlight = Math.max(highlight - 1, 0);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			if (totalOptions === 0) return;
			if (highlight < matches.length) add(matches[highlight].name);
			else if (canCreate) add(query.trim().toLowerCase());
		} else if (e.key === 'Backspace' && query === '' && value.length > 0) {
			remove(value[value.length - 1]);
		} else if (e.key === 'Escape') {
			focused = false;
		}
	}
</script>

<div class="wrap" bind:this={barEl}>
	<div
		class="bar"
		class:has-chips={value.length > 0}
		role="combobox"
		tabindex="-1"
		aria-expanded={focused}
		aria-haspopup="listbox"
		aria-controls="group-search-listbox"
		onclick={() => inputEl?.focus()}
		onkeydown={(e) => {
			if (e.key === 'Enter' || e.key === ' ') inputEl?.focus();
		}}
	>
		<span class="search-icon" aria-hidden="true"></span>
		{#each value as g (g)}
			{@const isNew = !available.some((x) => x.name === g)}
			<span class="chip">
				<span class="mono">{g}</span>
				{#if isNew}
					<span class="new-tag">new</span>
				{/if}
				<button
					type="button"
					class="x"
					aria-label="Remove {g}"
					onclick={(e) => {
						e.stopPropagation();
						remove(g);
					}}>✕</button
				>
			</span>
		{/each}
		<input
			bind:this={inputEl}
			bind:value={query}
			onfocus={() => (focused = true)}
			onkeydown={onKeyDown}
			placeholder={value.length === 0 ? placeholder : ''}
		/>
	</div>

	{#if focused && (matches.length > 0 || canCreate || query.trim().length > 0)}
		<div class="drop" id="group-search-listbox" role="listbox">
			{#each matches as g, i (g.name)}
				<button
					type="button"
					class="opt"
					class:active={i === highlight}
					onclick={() => add(g.name)}
					onmouseenter={() => (highlight = i)}
				>
					<span class="mono">{g.name}</span>
					{#if g.member_count !== undefined}
						<span class="count">
							{g.member_count}
							{g.member_count === 1 ? 'member' : 'members'}
						</span>
					{/if}
				</button>
			{/each}
			{#if canCreate}
				{@const i = matches.length}
				{#if matches.length > 0}
					<div class="sep"></div>
				{/if}
				<button
					type="button"
					class="opt create"
					class:active={i === highlight}
					onclick={() => add(query.trim().toLowerCase())}
					onmouseenter={() => (highlight = i)}
				>
					<span class="plus">+</span>
					<span>Create group <code class="mono">{query.trim().toLowerCase()}</code></span>
				</button>
			{/if}
			{#if matches.length === 0 && !canCreate && query.trim().length > 0}
				<div class="empty">Only lowercase letters, digits and dashes.</div>
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
		flex-wrap: wrap;
		gap: 6px;
		padding: 6px 10px;
		min-height: 36px;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-surface);
		cursor: text;
	}
	.bar.has-chips {
		padding: 5px 8px;
	}
	.bar:focus-within {
		border-color: var(--color-primary);
		outline: 2px solid var(--color-primary-bg);
		outline-offset: -1px;
	}
	.search-icon {
		width: 14px;
		height: 14px;
		border-radius: 50%;
		border: 1.5px solid var(--color-text-muted);
		position: relative;
		flex: none;
	}
	.search-icon::after {
		content: '';
		position: absolute;
		right: -3px;
		bottom: -3px;
		width: 6px;
		height: 1.5px;
		background: var(--color-text-muted);
		transform: rotate(45deg);
	}
	.chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 3px 6px 3px 8px;
		background: var(--color-primary-bg);
		color: var(--color-primary);
		border-radius: var(--radius-sm);
		font-size: 12px;
		font-weight: 500;
	}
	.chip .mono {
		font-family: var(--font-mono);
	}
	.chip .x {
		color: var(--color-text-muted);
		font-size: 10px;
		cursor: pointer;
		border: 0;
		background: transparent;
		padding: 0 2px;
	}
	.chip .x:hover {
		color: var(--color-danger);
	}
	.new-tag {
		font-size: 9px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--color-primary);
		opacity: 0.7;
		font-weight: 600;
	}
	input {
		flex: 1;
		min-width: 100px;
		border: 0;
		background: transparent;
		outline: 0;
		font-size: 13px;
		color: var(--color-text);
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
		padding: 7px 10px;
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
		font-size: 13px;
	}
	.count {
		font-size: 11px;
		color: var(--color-text-muted);
	}
	.create {
		gap: 8px;
		justify-content: flex-start;
	}
	.create .plus {
		font-size: 14px;
		width: 16px;
		text-align: center;
		color: var(--color-primary);
	}
	.create code {
		background: var(--color-primary-bg);
		padding: 1px 5px;
		border-radius: 3px;
		font-size: 11px;
	}
	.sep {
		height: 1px;
		background: var(--color-border-subtle);
		margin: 4px 6px;
	}
	.empty {
		padding: 8px 10px;
		font-size: 12px;
		color: var(--color-text-muted);
	}
</style>
