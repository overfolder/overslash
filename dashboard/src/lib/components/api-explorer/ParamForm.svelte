<script lang="ts">
	import type { ActionDetail, ActionParam, ExtraArg } from '$lib/types';

	let {
		detail,
		values,
		onchange,
		extras,
		onextraschange
	}: {
		detail: ActionDetail;
		values: Record<string, string>;
		onchange: (name: string, value: string) => void;
		/** Free-form rows for an action whose declared params are a floor
		 *  rather than a fence. Owned by the parent because the request
		 *  builder has to read them, same as `values`. */
		extras: ExtraArg[];
		onextraschange: (rows: ExtraArg[]) => void;
	} = $props();

	function sortEntries(params: Record<string, ActionParam>): [string, ActionParam][] {
		return Object.entries(params).sort(([aName, a], [bName, b]) => {
			if (a.required !== b.required) return a.required ? -1 : 1;
			return aName.localeCompare(bName);
		});
	}

	const entries = $derived(sortEntries(detail.params));

	/** `x-overslash-additional-properties`: the gateway will forward arguments
	 *  this template never declared, and treats a declared `enum` as the
	 *  members we know of rather than all of them. Both halves of the form
	 *  below hang off this — offering the extra rows without opening the enums
	 *  would leave the dashboard enforcing client-side exactly the constraint
	 *  the server stopped enforcing. */
	const relaxed = $derived(detail.additional_properties === true);

	function addExtra() {
		onextraschange([...extras, { key: '', value: '' }]);
	}

	function removeExtra(i: number) {
		onextraschange(extras.filter((_, n) => n !== i));
	}

	function editExtra(i: number, patch: Partial<ExtraArg>) {
		onextraschange(extras.map((row, n) => (n === i ? { ...row, ...patch } : row)));
	}

	/** param name → scope label, straight from the API. A param in here
	 *  contributes its value to the action's permission key, so the form says
	 *  so: it is the difference between a grant that covers this call and one
	 *  that does not. Params sharing a label (email's to/cc/bcc → `recipient`)
	 *  share a namespace. */
	const scopeLabels = $derived(
		new Map((detail.scope_param ?? []).map((s) => [s.param, s.label]))
	);

	function inputTypeOf(p: ActionParam): 'text' | 'number' | 'textarea' | 'select' | 'combo' {
		// An advisory enum keeps its members one click away but must stay
		// typable, so it becomes an `<input list>` rather than a `<select>`.
		if (p.enum && p.enum.length > 0) return relaxed ? 'combo' : 'select';
		if (p.type === 'integer' || p.type === 'number') return 'number';
		if (p.type === 'object' || p.type === 'array') return 'textarea';
		return 'text';
	}
</script>

<!-- An action with no declared params and `additional_properties` is exactly
     the case where the extra-args section is the only thing worth rendering,
     so the empty state must not swallow it. -->
{#if entries.length === 0 && !relaxed}
	<p class="empty">This action takes no parameters.</p>
{:else}
	<div class="form">
		{#each entries as [name, p] (name)}
			{@const kind = inputTypeOf(p)}
			<div class="row">
				<label class="label" for={`param-${name}`}>
					<span class="name">{name}{p.required ? ' *' : ''}</span>
					{#if scopeLabels.has(name)}
						<span class="scope" title="This value becomes part of the permission key checked for this call">
							scopes permission: {scopeLabels.get(name)}
						</span>
					{/if}
					{#if p.description}
						<span class="desc">{p.description}</span>
					{/if}
				</label>
				{#if kind === 'select'}
					<select
						id={`param-${name}`}
						class="control"
						value={values[name] ?? ''}
						onchange={(e) => onchange(name, (e.currentTarget as HTMLSelectElement).value)}
					>
						<option value="" disabled={p.required}>
							{p.required ? 'Select…' : '(empty)'}
						</option>
						{#each p.enum ?? [] as opt (opt)}
							<option value={opt}>{opt}</option>
						{/each}
					</select>
				{:else if kind === 'combo'}
					<input
						id={`param-${name}`}
						class="control"
						type="text"
						list={`param-${name}-options`}
						placeholder={p.description || name}
						value={values[name] ?? ''}
						oninput={(e) => onchange(name, (e.currentTarget as HTMLInputElement).value)}
					/>
					<datalist id={`param-${name}-options`}>
						{#each p.enum ?? [] as opt (opt)}
							<option value={opt}></option>
						{/each}
					</datalist>
				{:else if kind === 'textarea'}
					<textarea
						id={`param-${name}`}
						class="control mono"
						rows="3"
						placeholder={`JSON ${p.type}`}
						value={values[name] ?? ''}
						oninput={(e) => onchange(name, (e.currentTarget as HTMLTextAreaElement).value)}
					></textarea>
				{:else}
					<input
						id={`param-${name}`}
						class="control"
						type={kind}
						placeholder={p.description || name}
						value={values[name] ?? ''}
						oninput={(e) => onchange(name, (e.currentTarget as HTMLInputElement).value)}
					/>
				{/if}
			</div>
		{/each}

		{#if relaxed}
			<div class="extras">
				<div class="extras-head">
					<span class="name">Additional arguments</span>
					<span class="desc">
						This action accepts arguments beyond the ones above; they are
						forwarded upstream as sent. Names are not checked, so a typo is
						passed through rather than reported.
					</span>
				</div>
				{#each extras as row, i (i)}
					<div class="extra-row">
						<input
							class="control"
							type="text"
							placeholder="name"
							aria-label={`Additional argument ${i + 1} name`}
							value={row.key}
							oninput={(e) => editExtra(i, { key: (e.currentTarget as HTMLInputElement).value })}
						/>
						<input
							class="control"
							type="text"
							placeholder="value"
							aria-label={`Additional argument ${i + 1} value`}
							value={row.value}
							oninput={(e) => editExtra(i, { value: (e.currentTarget as HTMLInputElement).value })}
						/>
						<button type="button" class="extra-remove" onclick={() => removeExtra(i)} aria-label="Remove">
							&times;
						</button>
					</div>
				{/each}
				<button type="button" class="extra-add" onclick={addExtra}>+ Add argument</button>
			</div>
		{/if}
	</div>
{/if}

<style>
	.form {
		display: flex;
		flex-direction: column;
		gap: 0.9rem;
	}
	.row {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.label {
		display: flex;
		flex-direction: column;
		gap: 0.1rem;
	}
	.name {
		font: var(--text-label);
		color: var(--color-text);
	}
	.desc {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
	.scope {
		align-self: flex-start;
		margin: 0.15rem 0;
		padding: 0.1rem 0.4rem;
		font-size: 0.68rem;
		letter-spacing: 0.02em;
		color: var(--color-text);
		background: var(--color-surface-alt, var(--color-surface));
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
	}
	.control {
		width: 100%;
		padding: 0.55rem 0.75rem;
		font: inherit;
		font-size: 0.88rem;
		color: var(--color-text);
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
	}
	.control:focus {
		outline: 2px solid var(--color-primary);
		outline-offset: -1px;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.empty {
		font-size: 0.85rem;
		color: var(--color-text-muted);
		margin: 0;
	}
	.extras {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding-top: 0.9rem;
		border-top: 1px solid var(--color-border);
	}
	.extras-head {
		display: flex;
		flex-direction: column;
		gap: 0.1rem;
	}
	.extra-row {
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(0, 2fr) auto;
		gap: 0.4rem;
		align-items: center;
	}
	.extra-remove,
	.extra-add {
		font: inherit;
		color: var(--color-text-muted);
		background: none;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		cursor: pointer;
	}
	.extra-remove {
		width: 2rem;
		height: 2rem;
		font-size: 1rem;
		line-height: 1;
	}
	.extra-add {
		align-self: flex-start;
		padding: 0.35rem 0.7rem;
		font-size: 0.82rem;
	}
	.extra-remove:hover,
	.extra-add:hover {
		color: var(--color-text);
		border-color: var(--color-text-muted);
	}
</style>
