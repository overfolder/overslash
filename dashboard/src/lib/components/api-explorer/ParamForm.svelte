<script lang="ts">
	import type { ActionDetail, ActionParam } from '$lib/types';

	let {
		detail,
		values,
		onchange
	}: {
		detail: ActionDetail;
		values: Record<string, string>;
		onchange: (name: string, value: string) => void;
	} = $props();

	function sortEntries(params: Record<string, ActionParam>): [string, ActionParam][] {
		return Object.entries(params).sort(([aName, a], [bName, b]) => {
			if (a.required !== b.required) return a.required ? -1 : 1;
			return aName.localeCompare(bName);
		});
	}

	const entries = $derived(sortEntries(detail.params));

	/** param name → scope label, straight from the API. A param in here
	 *  contributes its value to the action's permission key, so the form says
	 *  so: it is the difference between a grant that covers this call and one
	 *  that does not. Params sharing a label (email's to/cc/bcc → `recipient`)
	 *  share a namespace. */
	const scopeLabels = $derived(
		new Map((detail.scope_param ?? []).map((s) => [s.param, s.label]))
	);

	function inputTypeOf(p: ActionParam): 'text' | 'number' | 'textarea' | 'select' {
		if (p.enum && p.enum.length > 0) return 'select';
		if (p.type === 'integer' || p.type === 'number') return 'number';
		if (p.type === 'object' || p.type === 'array') return 'textarea';
		return 'text';
	}
</script>

{#if entries.length === 0}
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
</style>
