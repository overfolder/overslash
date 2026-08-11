<script lang="ts" module>
	// The model lives in a plain `.ts` so it can be unit-tested; it is re-exported
	// here because every consumer imports its types from this component.
	import {
		addTerm,
		addTerms,
		emptySearch,
		filterTerms,
		hasTerm,
		matchesAllText,
		parseSearch,
		removeTermAt,
		sameTerm,
		termId,
		termToDraft,
		textTerms
	} from '$lib/search/terms';
	import type {
		FilterTerm,
		Operator,
		SearchKey,
		SearchValue,
		Term,
		TextTerm
	} from '$lib/search/terms';

	export {
		addTerm,
		addTerms,
		emptySearch,
		filterTerms,
		hasTerm,
		matchesAllText,
		parseSearch,
		removeTermAt,
		sameTerm,
		termId,
		termToDraft,
		textTerms
	};
	export type { FilterTerm, Operator, SearchKey, SearchValue, Term, TextTerm };
</script>

<script lang="ts">
	import { tick, untrack } from 'svelte';

	let {
		keys,
		value = $bindable(),
		pinned = [],
		placeholder = 'Search…',
		onchange,
		onremovepinned
	}: {
		keys: SearchKey[];
		value: SearchValue;
		/** Filters owned by the URL rather than by the bar (`?connection=<id>`).
		 *  Rendered first, not editable, removed through `onremovepinned`. */
		pinned?: FilterTerm[];
		placeholder?: string;
		onchange: (next: SearchValue) => void;
		onremovepinned?: (term: FilterTerm, index: number) => void;
	} = $props();

	// A `key` suggestion carries its `key`/`op` directly so selecting it can set
	// the pending operator without re-parsing a label. A `value` suggestion
	// carries the value to insert in `insert`.
	type Suggestion =
		| { kind: 'key'; label: string; key: SearchKey; op: Operator }
		| { kind: 'value'; label: string; insert: string };

	let inputEl: HTMLInputElement | undefined = $state();
	// Uncommitted text only. Nothing here is part of `value` until it is
	// committed into a bubble (Enter, blur, or picking a suggestion).
	let draft = $state('');
	let suggestions = $state<Suggestion[]>([]);
	let showSuggestions = $state(false);
	let activeIndex = $state(0);
	let pendingKey = $state<SearchKey | null>(null);
	let pendingOp = $state<Operator>('=');
	let pendingValues = $state<string[]>([]);
	let debounceTimer: ReturnType<typeof setTimeout> | undefined;
	// Fires ~2s after the (empty) input is focused to reveal the full key list,
	// helping users discover what's filterable without typing first.
	let idleTimer: ReturnType<typeof setTimeout> | undefined;
	const IDLE_KEYS_DELAY = 2000;

	const knownKeyNames = $derived(keys.map((k) => k.name));

	function emit(next: SearchValue) {
		onchange(next);
	}

	function removeTerm(index: number) {
		emit(removeTermAt(value, index));
		inputEl?.focus();
	}

	/** Commit one term and reset the input to its resting state. A duplicate is
	 *  swallowed rather than emitted — on the audit page an emit costs a refetch. */
	function commit(term: Term) {
		const next = addTerm(value, term);
		draft = '';
		pendingKey = null;
		showSuggestions = false;
		if (next !== value) emit(next);
	}

	/** Turn whatever is typed into bubbles. `key op value` (typed in full, or
	 *  half-picked from the dropdown) becomes a filter bubble; every remaining
	 *  gap becomes one text bubble. */
	function commitDraft() {
		if (!draft.trim()) return;
		if (pendingKey) {
			commit({ kind: 'filter', key: pendingKey.name, op: pendingOp, value: draft.trim() });
			return;
		}
		const next = addTerms(value, parseSearch(draft, knownKeyNames));
		draft = '';
		showSuggestions = false;
		if (next !== value) emit(next);
	}

	/** Click a bubble to fix a typo: it leaves the bar and returns to the input,
	 *  a filter reopening in its `key op …` pending state so value autocomplete
	 *  still works on the second pass. */
	async function editTerm(index: number) {
		const t = value.terms[index];
		if (!t) return;
		clearIdleKeys();
		if (t.kind === 'text') {
			pendingKey = null;
			draft = t.value;
		} else {
			const key = keys.find((k) => k.name === t.key) ?? null;
			pendingKey = key;
			pendingOp = t.op;
			pendingValues = [];
			// A filter whose key this surface no longer offers can't reopen as a
			// pending chip — hand it back as editable text instead of dropping it.
			draft = key ? t.value : termToDraft(t);
		}
		emit(removeTermAt(value, index));
		await tick();
		inputEl?.focus();
		recompute();
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

	/** One suggestion per (key × operator) so users can pick the operator too —
	 *  e.g. `user` offers both `user = …` and `user ~ …`. */
	function keySuggestions(matches: SearchKey[]): Suggestion[] {
		return matches.flatMap((k) => {
			const ops = k.operators?.length ? k.operators : (['='] as Operator[]);
			return ops.map((op) => ({
				kind: 'key' as const,
				label: k.hint ? `${k.name} ${op} …  · ${k.hint}` : `${k.name} ${op} …`,
				key: k,
				op
			}));
		});
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
		// Key (+ operator) autocomplete from the first character of a key prefix.
		const trimmed = draft.trimStart();
		if (trimmed.length < 1) {
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
		suggestions = keySuggestions(matches);
		showSuggestions = true;
		activeIndex = 0;
	}

	/** Reveal the full key list (every key × operator) — fired ~2s after the
	 *  empty input is focused, so the bar is self-documenting. */
	function showAllKeys() {
		if (pendingKey || draft.trim() !== '') return;
		suggestions = keySuggestions(keys);
		showSuggestions = suggestions.length > 0;
		activeIndex = 0;
	}

	function scheduleIdleKeys() {
		clearIdleKeys();
		idleTimer = setTimeout(showAllKeys, IDLE_KEYS_DELAY);
	}

	function clearIdleKeys() {
		if (idleTimer) clearTimeout(idleTimer);
		idleTimer = undefined;
	}

	function scheduleRecompute() {
		if (debounceTimer) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(recompute, 200);
	}

	async function onInput() {
		// Typing supersedes the idle key-list reveal.
		clearIdleKeys();
		scheduleRecompute();
	}

	function onFocus() {
		recompute();
		scheduleIdleKeys();
	}

	async function selectSuggestion(i: number) {
		const s = suggestions[i];
		if (!s) return;
		clearIdleKeys();
		if (s.kind === 'key') {
			pendingKey = s.key;
			pendingOp = s.op;
			pendingValues = [];
			draft = '';
			await tick();
			inputEl?.focus();
			recompute();
		} else if (s.kind === 'value' && pendingKey) {
			commit({ kind: 'filter', key: pendingKey.name, op: pendingOp, value: s.insert });
		}
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
			commitDraft();
		} else if (e.key === 'Backspace' && draft === '' && pendingKey) {
			pendingKey = null;
			recompute();
		} else if (e.key === 'Backspace' && draft === '' && value.terms.length > 0) {
			removeTerm(value.terms.length - 1);
		}
	}

	function onBlur() {
		clearIdleKeys();
		// Commit on the way out so nothing typed is silently dropped (and the
		// audit page's URL stays in sync).
		commitDraft();
		// Delay hiding so click on suggestion still fires.
		setTimeout(() => (showSuggestions = false), 150);
	}

	$effect(() => {
		// Parent reset the bar (a "Clear filters" button, a navigation) — drop any
		// uncommitted text with it, unless the user is mid-type in the field.
		if (value.terms.length !== 0) return;
		untrack(() => {
			if (draft !== '' && document.activeElement !== inputEl) draft = '';
		});
	});

	function editLabel(t: Term): string {
		return t.kind === 'text'
			? `Edit search term ${t.value}`
			: `Edit filter ${t.key} ${t.op} ${t.label ?? t.value}`;
	}

	function removeLabel(t: Term): string {
		return t.kind === 'text'
			? `Remove search term ${t.value}`
			: `Remove filter ${t.key} ${t.op} ${t.label ?? t.value}`;
	}
</script>

<div class="search">
	<div class="field" onclick={() => inputEl?.focus()} role="presentation">
		{#each pinned as t, i (i)}
			<span class="chip is-pinned">
				<span class="chip-body">
					<span class="chip-key">{t.key}</span>
					<span class="chip-op">{t.op}</span>
					<span class="chip-val">{t.label ?? t.value}</span>
				</span>
				{#if onremovepinned}
					<button
						type="button"
						class="chip-remove"
						aria-label={removeLabel(t)}
						onmousedown={(e) => e.preventDefault()}
						onclick={(e) => {
							e.stopPropagation();
							onremovepinned?.(t, i);
						}}>✕</button
					>
				{/if}
			</span>
		{/each}
		<!-- Keyed by index, not by term: chips hold no local state, the index *is*
		     the remove/edit handle, and a hand-crafted URL (`?tag=a,a`) can hydrate
		     two identical terms, which a value-based key would crash on. -->
		{#each value.terms as t, i (i)}
			<span class="chip" class:is-text={t.kind === 'text'}>
				<!-- mousedown is swallowed so the field never blurs mid-click, which
				     would commit the draft (and re-index the terms) under our feet. -->
				<button
					type="button"
					class="chip-body"
					aria-label={editLabel(t)}
					onmousedown={(e) => e.preventDefault()}
					onclick={(e) => {
						e.stopPropagation();
						editTerm(i);
					}}
				>
					{#if t.kind === 'text'}
						<span class="chip-ico" aria-hidden="true">⌕</span>
						<span class="chip-val">{t.value}</span>
					{:else}
						<span class="chip-key">{t.key}</span>
						<span class="chip-op">{t.op}</span>
						<span class="chip-val">{t.label ?? t.value}</span>
					{/if}
				</button>
				<button
					type="button"
					class="chip-remove"
					aria-label={removeLabel(t)}
					onmousedown={(e) => e.preventDefault()}
					onclick={(e) => {
						e.stopPropagation();
						removeTerm(i);
					}}>✕</button
				>
			</span>
		{/each}
		{#if pendingKey}
			<span class="chip is-pending">
				<span class="chip-body">
					<span class="chip-key">{pendingKey.name}</span>
					<span class="chip-op">{pendingOp}</span>
				</span>
			</span>
		{/if}
		<input
			bind:this={inputEl}
			bind:value={draft}
			oninput={onInput}
			onkeydown={onKeydown}
			onblur={onBlur}
			onfocus={onFocus}
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
		/* `--color-primary-bg` / `--color-primary` both carry dark-mode overrides;
		   the older `--primary-50` / `--primary-700` pair did not, which left chip
		   text as dark indigo on a translucent field in dark mode. */
		background: var(--color-primary-bg);
		color: var(--color-primary);
		border-radius: 4px;
		font-size: 0.85rem;
		max-width: 100%;
	}
	/* Text bubbles read as "words I searched for", filters as "column = value" —
	   a neutral tint plus the glyph keeps the two apart at a glance. */
	.chip.is-text,
	.chip.is-pending {
		background: var(--neutral-100, #f5f5f7);
		color: var(--color-text);
	}
	.chip.is-pinned {
		background: var(--neutral-100, #f5f5f7);
		color: var(--color-text-muted);
	}
	.chip-body {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-width: 0;
		padding: 2px 4px 2px 8px;
		border: none;
		background: transparent;
		color: inherit;
		font: inherit;
		font-size: inherit;
		text-align: left;
	}
	button.chip-body {
		cursor: pointer;
	}
	.chip-key {
		font-weight: 600;
	}
	.chip-op {
		opacity: 0.7;
	}
	.chip-ico {
		opacity: 0.6;
	}
	.chip-val {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.chip-remove {
		border: none;
		background: transparent;
		color: inherit;
		cursor: pointer;
		font-size: 0.85rem;
		padding: 2px 6px 2px 2px;
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
		background: var(--color-primary-bg);
		color: var(--color-primary);
	}
</style>
