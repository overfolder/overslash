<script lang="ts" module>
	export type Operator = '=' | '~' | '!=';

	export interface SearchKey {
		/** Key name shown to the user (e.g. `event`, `identity`). */
		name: string;
		/** Allowed operators. Defaults to `['=']`. */
		operators?: Operator[];
		/** Static value list, or an async loader for value autocomplete. */
		values?: string[] | (() => Promise<string[]>);
		/** Help text shown next to the key suggestion. */
		hint?: string;
	}

	export interface Expression {
		key: string;
		op: Operator;
		value: string;
	}

	export interface SearchValue {
		expressions: Expression[];
		freeText: string;
	}

	const TOKEN_RE = /(\w+)\s*(!=|=|~)\s*("[^"]*"|\S+)/g;

	/** Parse a free string into structured expressions + remaining free text. */
	export function parseSearch(input: string, knownKeys: string[]): SearchValue {
		const expressions: Expression[] = [];
		let lastIndex = 0;
		let freeText = '';
		const re = new RegExp(TOKEN_RE);
		let m: RegExpExecArray | null;
		while ((m = re.exec(input)) !== null) {
			const [full, key, op, rawValue] = m;
			if (!knownKeys.includes(key)) continue;
			freeText += input.slice(lastIndex, m.index);
			lastIndex = m.index + full.length;
			const value = rawValue.startsWith('"') ? rawValue.slice(1, -1) : rawValue;
			expressions.push({ key, op: op as Operator, value });
		}
		freeText += input.slice(lastIndex);
		return { expressions, freeText: freeText.replace(/\s+/g, ' ').trim() };
	}
</script>

<script lang="ts">
	import { tick } from 'svelte';

	let {
		keys,
		value = $bindable(),
		placeholder = 'Search…',
		onchange
	}: {
		keys: SearchKey[];
		value: SearchValue;
		placeholder?: string;
		onchange: (next: SearchValue) => void;
	} = $props();

	let inputEl: HTMLInputElement | undefined = $state();
	let draft = $state(value.freeText);
	let suggestions = $state<{ kind: 'key' | 'value'; label: string; insert: string }[]>([]);
	let showSuggestions = $state(false);
	let activeIndex = $state(0);
	let pendingKey = $state<SearchKey | null>(null);
	let pendingOp = $state<Operator>('=');
	let pendingValues = $state<string[]>([]);
	let debounceTimer: ReturnType<typeof setTimeout> | undefined;

	const knownKeyNames = $derived(keys.map((k) => k.name));

	function emit(next: SearchValue) {
		onchange(next);
	}

	function removeChip(index: number) {
		const next: SearchValue = {
			expressions: value.expressions.filter((_, i) => i !== index),
			freeText: draft.trim()
		};
		emit(next);
		inputEl?.focus();
	}

	function addExpression(expr: Expression) {
		const next: SearchValue = {
			expressions: [...value.expressions, expr],
			freeText: ''
		};
		draft = '';
		pendingKey = null;
		showSuggestions = false;
		emit(next);
	}

	async function loadValues(key: SearchKey): Promise<string[]> {
		if (!key.values) return [];
		if (Array.isArray(key.values)) return key.values;
		try {
			return await key.values();
		} catch {
			return [];
		}
	}

	async function recompute() {
		// If we're in "value entry" mode for a key, show value suggestions.
		if (pendingKey) {
			const list = pendingValues.length ? pendingValues : await loadValues(pendingKey);
			pendingValues = list;
			const term = draft.toLowerCase();
			suggestions = list
				.filter((v) => v.toLowerCase().includes(term))
				.slice(0, 8)
				.map((v) => ({ kind: 'value', label: v, insert: v }));
			showSuggestions = suggestions.length > 0;
			activeIndex = 0;
			return;
		}
		// Key autocomplete after 3+ chars matching a known key prefix.
		const trimmed = draft.trimStart();
		if (trimmed.length < 3) {
			suggestions = [];
			showSuggestions = false;
			return;
		}
		const lower = trimmed.toLowerCase();
		const matches = keys.filter((k) => k.name.toLowerCase().startsWith(lower));
		if (!matches.length) {
			suggestions = [];
			showSuggestions = false;
			return;
		}
		suggestions = matches.map((k) => ({
			kind: 'key',
			label: k.hint ? `${k.name} = …  · ${k.hint}` : `${k.name} = …`,
			insert: `${k.name} = `
		}));
		showSuggestions = true;
		activeIndex = 0;
	}

	function scheduleRecompute() {
		if (debounceTimer) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(recompute, 200);
	}

	async function onInput() {
		scheduleRecompute();
	}

	async function selectSuggestion(i: number) {
		const s = suggestions[i];
		if (!s) return;
		if (s.kind === 'key') {
			const key = keys.find((k) => k.name === s.insert.split(' ')[0])!;
			pendingKey = key;
			pendingOp = key.operators?.[0] ?? '=';
			pendingValues = [];
			draft = '';
			await tick();
			inputEl?.focus();
			recompute();
		} else if (s.kind === 'value' && pendingKey) {
			addExpression({ key: pendingKey.name, op: pendingOp, value: s.insert });
		}
	}

	function commitFromInput() {
		// Try parsing what's typed as `key op value` (no autocomplete needed).
		const parsed = parseSearch(draft, knownKeyNames);
		if (parsed.expressions.length) {
			emit({
				expressions: [...value.expressions, ...parsed.expressions],
				freeText: parsed.freeText
			});
			draft = parsed.freeText;
			return;
		}
		// In pendingKey mode, treat the whole draft as the value.
		if (pendingKey && draft.trim()) {
			addExpression({ key: pendingKey.name, op: pendingOp, value: draft.trim() });
			return;
		}
		// Otherwise emit free text as-is.
		emit({ expressions: value.expressions, freeText: draft.trim() });
	}

	function onKeydown(e: KeyboardEvent) {
		if (showSuggestions) {
			if (e.key === 'ArrowDown') {
				e.preventDefault();
				activeIndex = (activeIndex + 1) % suggestions.length;
				return;
			}
			if (e.key === 'ArrowUp') {
				e.preventDefault();
				activeIndex = (activeIndex - 1 + suggestions.length) % suggestions.length;
				return;
			}
			if (e.key === 'Enter' || e.key === 'Tab') {
				e.preventDefault();
				selectSuggestion(activeIndex);
				return;
			}
			if (e.key === 'Escape') {
				showSuggestions = false;
				return;
			}
		}
		if (e.key === 'Enter') {
			e.preventDefault();
			commitFromInput();
		} else if (e.key === 'Backspace' && draft === '' && pendingKey) {
			pendingKey = null;
			recompute();
		} else if (e.key === 'Backspace' && draft === '' && value.expressions.length > 0) {
			removeChip(value.expressions.length - 1);
		}
	}

	function onBlur() {
		// Commit free text on blur so URL stays in sync.
		commitFromInput();
		// Delay hiding so click on suggestion still fires.
		setTimeout(() => (showSuggestions = false), 150);
	}

	$effect(() => {
		// Sync external value back into draft when parent resets filters.
		if (value.freeText !== draft && document.activeElement !== inputEl) {
			draft = value.freeText;
		}
	});
</script>

<div class="search">
	<div class="field" onclick={() => inputEl?.focus()} role="presentation">
		{#each value.expressions as expr, i (i + expr.key + expr.value)}
			<span class="chip">
				<span class="chip-key">{expr.key}</span>
				<span class="chip-op">{expr.op}</span>
				<span class="chip-val">{expr.value}</span>
				<button
					type="button"
					class="chip-remove"
					aria-label="Remove filter"
					onclick={(e) => {
						e.stopPropagation();
						removeChip(i);
					}}>✕</button
				>
			</span>
		{/each}
		{#if pendingKey}
			<span class="chip pending">
				<span class="chip-key">{pendingKey.name}</span>
				<span class="chip-op">{pendingOp}</span>
			</span>
		{/if}
		<input
			bind:this={inputEl}
			bind:value={draft}
			oninput={onInput}
			onkeydown={onKeydown}
			onblur={onBlur}
			onfocus={recompute}
			{placeholder}
			autocomplete="off"
			spellcheck="false"
		/>
	</div>
	{#if showSuggestions}
		<ul class="suggestions" role="listbox">
			{#each suggestions as s, i}
				<li>
					<button
						type="button"
						class:active={i === activeIndex}
						onmousedown={(e) => {
							e.preventDefault();
							selectSuggestion(i);
						}}
					>
						{s.label}
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<style>
	.search {
		position: relative;
		width: 100%;
	}
	.field {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 6px;
		padding: 6px 10px;
		background: var(--color-surface, #fff);
		border: 1px solid var(--neutral-200, #e8e8ee);
		border-radius: 8px;
		min-height: 40px;
		cursor: text;
	}
	.field:focus-within {
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px var(--primary-50, #ededff);
	}
	input {
		flex: 1 1 120px;
		min-width: 120px;
		border: none;
		outline: none;
		background: transparent;
		font: inherit;
		color: var(--color-text);
	}
	input::placeholder {
		color: var(--color-text-placeholder);
	}
	.chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 2px 6px 2px 8px;
		background: var(--primary-50, #ededff);
		color: var(--primary-700, #4238a8);
		border-radius: 4px;
		font-size: 0.85rem;
	}
	.chip.pending {
		background: var(--neutral-100, #f5f5f7);
		color: var(--color-text);
	}
	.chip-key {
		font-weight: 600;
	}
	.chip-op {
		opacity: 0.7;
	}
	.chip-remove {
		border: none;
		background: transparent;
		color: inherit;
		cursor: pointer;
		font-size: 0.85rem;
		padding: 0 2px;
		line-height: 1;
	}
	.chip-remove:hover {
		color: var(--color-danger);
	}
	.suggestions {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		z-index: 30;
		margin: 0;
		padding: 4px;
		list-style: none;
		background: var(--color-surface, #fff);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
		max-height: 240px;
		overflow-y: auto;
	}
	.suggestions button {
		display: block;
		width: 100%;
		text-align: left;
		padding: 6px 10px;
		border: none;
		background: transparent;
		color: var(--color-text);
		cursor: pointer;
		border-radius: 4px;
		font: inherit;
	}
	.suggestions button.active,
	.suggestions button:hover {
		background: var(--primary-50, #ededff);
		color: var(--primary-700, #4238a8);
	}
</style>
