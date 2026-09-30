<script lang="ts">
	/**
	 * A free-text chip input: type a value, press Enter (or comma / space /
	 * Tab), and it becomes a pill.
	 *
	 * Sibling of `GroupSearch` and `PillPicker` rather than a mode of either:
	 * both of those pick from a known list (with a dropdown), while this one
	 * accepts arbitrary values — email domains, hostnames — that have no list
	 * to pick from. It borrows GroupSearch's chip look so the two read as one
	 * control family.
	 *
	 * `normalize` runs on every candidate before `validate`; a candidate that
	 * fails validation stays in the text field with the error shown under it,
	 * so the user can fix it instead of retyping.
	 */

	let {
		value = $bindable<string[]>([]),
		placeholder = '',
		disabled = false,
		ariaLabel,
		normalize = (s: string) => s.trim(),
		validate
	}: {
		value: string[];
		placeholder?: string;
		disabled?: boolean;
		ariaLabel?: string;
		normalize?: (s: string) => string;
		/** Returns an error message, or null when the value is acceptable. */
		validate?: (s: string) => string | null;
	} = $props();

	let query = $state('');
	let error = $state<string | null>(null);
	let inputEl: HTMLInputElement | undefined = $state();

	/**
	 * Turn `raw` (possibly several values separated by commas / whitespace)
	 * into pills. Invalid pieces are put back in the field.
	 */
	function commit(raw: string) {
		const pieces = raw
			.split(/[\s,]+/)
			.map(normalize)
			.filter((s) => s.length > 0);
		const rejected: string[] = [];
		let next = value;
		let firstError: string | null = null;
		for (const p of pieces) {
			const err = validate?.(p) ?? null;
			if (err) {
				rejected.push(p);
				firstError ??= err;
				continue;
			}
			if (!next.includes(p)) next = [...next, p];
		}
		if (next !== value) value = next;
		query = rejected.join(', ');
		error = firstError;
	}

	function remove(item: string) {
		value = value.filter((v) => v !== item);
	}

	function onKeyDown(e: KeyboardEvent) {
		if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
			e.preventDefault();
			commit(query);
		} else if (e.key === 'Tab' && query.trim() !== '') {
			e.preventDefault();
			commit(query);
		} else if (e.key === 'Backspace' && query === '' && value.length > 0) {
			remove(value[value.length - 1]);
		}
	}

	function onPaste(e: ClipboardEvent) {
		const text = e.clipboardData?.getData('text') ?? '';
		if (!/[\s,]/.test(text)) return;
		e.preventDefault();
		commit(query + text);
	}
</script>

<div class="chip-input">
	<div
		class="bar"
		class:has-chips={value.length > 0}
		class:invalid={error !== null}
		class:disabled
		role="presentation"
		onclick={() => inputEl?.focus()}
	>
		{#each value as item (item)}
			<span class="chip">
				<span class="mono">{item}</span>
				<button
					type="button"
					class="x"
					aria-label="Remove {item}"
					{disabled}
					onclick={(e) => {
						e.stopPropagation();
						remove(item);
					}}>✕</button
				>
			</span>
		{/each}
		<input
			bind:this={inputEl}
			bind:value={query}
			oninput={() => (error = null)}
			onkeydown={onKeyDown}
			onpaste={onPaste}
			onblur={() => {
				if (query.trim() !== '') commit(query);
			}}
			placeholder={value.length === 0 ? placeholder : ''}
			aria-label={ariaLabel}
			aria-invalid={error !== null}
			{disabled}
		/>
	</div>
	{#if error}
		<div class="error">{error}</div>
	{/if}
</div>

<style>
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
	.bar.invalid {
		border-color: var(--color-danger);
	}
	.bar.disabled {
		opacity: 0.6;
		cursor: default;
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
	.chip .x:hover:not(:disabled) {
		color: var(--color-danger);
	}
	input {
		flex: 1;
		min-width: 120px;
		border: 0;
		background: transparent;
		outline: 0;
		font-size: 13px;
		font-family: var(--font-mono);
		color: var(--color-text);
	}
	input::placeholder {
		color: var(--color-text-muted);
	}
	.error {
		margin-top: 4px;
		font-size: 12px;
		color: var(--color-danger);
	}
</style>
