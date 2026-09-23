<script lang="ts">
	/**
	 * A row of pills plus a `+` button that opens a searchable dropdown.
	 *
	 * Split out from `GroupSearch` rather than reusing it: that one is a chip
	 * *input* — an always-open text field you type into, right for a create-form
	 * field. This is for a relationship that already exists and is edited
	 * occasionally, where a permanently-open search box reads as an unfinished
	 * form. The `+` keeps the resting state quiet and the dropdown only appears
	 * on intent.
	 *
	 * Adding and removing are async and owned by the caller, so the picker holds
	 * no list state of its own — it renders what it is handed and reports
	 * intent. `busy` disables everything while a call is in flight.
	 */

	interface PillOption {
		id: string;
		label: string;
		/** Second line in the dropdown row — a raw id, a count, whatever. */
		hint?: string;
	}

	let {
		selected = [],
		options = [],
		busy = false,
		disabled = false,
		placeholder = 'Search…',
		addLabel = 'Add',
		emptyText = 'None',
		noOptionsText = 'Nothing to add',
		onAdd,
		onRemove
	}: {
		selected?: PillOption[];
		/** Everything addable. Already-selected entries are filtered out here. */
		options?: PillOption[];
		busy?: boolean;
		disabled?: boolean;
		placeholder?: string;
		addLabel?: string;
		emptyText?: string;
		noOptionsText?: string;
		onAdd: (id: string) => void;
		onRemove?: (id: string) => void;
	} = $props();

	let open = $state(false);
	let query = $state('');
	let highlight = $state(0);
	let wrapEl: HTMLDivElement | undefined = $state();
	let inputEl: HTMLInputElement | undefined = $state();

	const selectedIds = $derived(new Set(selected.map((s) => s.id)));

	const matches = $derived.by(() => {
		const pool = options.filter((o) => !selectedIds.has(o.id));
		const q = query.trim().toLowerCase();
		if (!q) return pool.slice(0, 8);
		return pool
			.filter(
				(o) =>
					o.label.toLowerCase().includes(q) || (o.hint ?? '').toLowerCase().includes(q)
			)
			.slice(0, 8);
	});

	$effect(() => {
		if (!open) return;
		const onDoc = (e: MouseEvent) => {
			if (wrapEl && !wrapEl.contains(e.target as Node)) close();
		};
		document.addEventListener('mousedown', onDoc);
		return () => document.removeEventListener('mousedown', onDoc);
	});

	// Keep the highlight in range as the filter narrows, otherwise Enter can
	// fire on a row that is no longer rendered.
	$effect(() => {
		void query;
		void open;
		highlight = 0;
	});

	function toggle() {
		if (disabled || busy) return;
		open = !open;
		if (open) {
			query = '';
			queueMicrotask(() => inputEl?.focus());
		}
	}

	function close() {
		open = false;
		query = '';
	}

	function pick(id: string) {
		close();
		onAdd(id);
	}

	function onKeyDown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			highlight = Math.min(highlight + 1, matches.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			highlight = Math.max(highlight - 1, 0);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			if (matches.length > 0) pick(matches[highlight].id);
		} else if (e.key === 'Escape') {
			e.preventDefault();
			close();
		}
	}
</script>

<div class="wrap" bind:this={wrapEl}>
	<div class="pills">
		{#if selected.length === 0}
			<span class="empty">{emptyText}</span>
		{:else}
			{#each selected as p (p.id)}
				<span class="pill">
					<span class="pill-label">{p.label}</span>
					{#if onRemove}
						<button
							type="button"
							class="pill-x"
							aria-label="Remove {p.label}"
							disabled={busy || disabled}
							onclick={() => onRemove?.(p.id)}>✕</button
						>
					{/if}
				</span>
			{/each}
		{/if}

		<button
			type="button"
			class="add"
			aria-label={addLabel}
			aria-expanded={open}
			aria-haspopup="listbox"
			disabled={disabled || busy}
			onclick={toggle}
		>
			<span aria-hidden="true">+</span>
		</button>
	</div>

	{#if open}
		<div class="drop">
			<input
				bind:this={inputEl}
				bind:value={query}
				class="search"
				type="text"
				{placeholder}
				onkeydown={onKeyDown}
			/>
			<div class="opts" role="listbox">
				{#each matches as o, i (o.id)}
					<button
						type="button"
						class="opt"
						class:active={i === highlight}
						role="option"
						aria-selected={i === highlight}
						onclick={() => pick(o.id)}
						onmouseenter={() => (highlight = i)}
					>
						<span class="opt-label">{o.label}</span>
						{#if o.hint}<span class="opt-hint">{o.hint}</span>{/if}
					</button>
				{:else}
					<div class="no-opts">
						{query.trim() ? 'No matches' : noOptionsText}
					</div>
				{/each}
			</div>
		</div>
	{/if}
</div>

<style>
	.wrap {
		position: relative;
		display: inline-block;
	}
	.pills {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
	}
	.empty {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.pill {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: 2px var(--space-2);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-pill);
		background: var(--color-surface);
		font: var(--text-body-sm);
		color: var(--color-text);
	}
	.pill-x {
		display: inline-flex;
		border: none;
		background: none;
		padding: 0;
		cursor: pointer;
		color: var(--color-text-muted);
		font-size: 10px;
		line-height: 1;
	}
	.pill-x:hover:not(:disabled) {
		color: var(--color-danger);
	}
	.pill-x:disabled {
		cursor: default;
		opacity: 0.5;
	}

	.add {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 22px;
		height: 22px;
		padding: 0;
		border: 1px dashed var(--color-border);
		border-radius: var(--radius-pill);
		background: transparent;
		color: var(--color-text-muted);
		cursor: pointer;
		font-size: 14px;
		line-height: 1;
	}
	.add:hover:not(:disabled) {
		border-style: solid;
		border-color: var(--color-primary);
		color: var(--color-primary);
	}
	.add:disabled {
		cursor: default;
		opacity: 0.5;
	}

	.drop {
		position: absolute;
		z-index: 40;
		top: calc(100% + var(--space-2));
		left: 0;
		min-width: 260px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-lg);
		overflow: hidden;
	}
	.search {
		width: 100%;
		box-sizing: border-box;
		padding: var(--space-2) var(--space-3);
		border: none;
		border-bottom: 1px solid var(--color-border-subtle);
		background: transparent;
		color: var(--color-text);
		font: var(--text-body);
	}
	.search:focus {
		outline: none;
	}
	.opts {
		max-height: 240px;
		overflow-y: auto;
	}
	.opt {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 1px;
		width: 100%;
		padding: var(--space-2) var(--space-3);
		border: none;
		background: transparent;
		text-align: left;
		cursor: pointer;
	}
	.opt.active {
		background: var(--color-primary-bg);
	}
	.opt-label {
		font: var(--text-body);
		color: var(--color-text);
	}
	.opt-hint {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		font-family: var(--font-mono);
	}
	.no-opts {
		padding: var(--space-3);
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
</style>
