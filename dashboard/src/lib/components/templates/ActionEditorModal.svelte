<script lang="ts">
	import type { ActionParam, ServiceAction } from '$lib/types';

	type ActionWithKey = ServiceAction & { key: string };

	let {
		action = null,
		readOnly = false,
		onsave,
		ondelete,
		oncancel
	}: {
		action?: ActionWithKey | null;
		readOnly?: boolean;
		onsave: (key: string, action: ServiceAction) => void;
		ondelete?: (key: string) => void;
		oncancel: () => void;
	} = $props();

	const isEdit = $derived(action !== null);

	let key = $state(action?.key ?? '');
	let method = $state(action?.method ?? 'GET');
	let path = $state(action?.path ?? '');
	let description = $state(action?.description ?? '');
	let risk = $state(action?.risk ?? 'low');
	let responseType = $state(action?.response_type ?? '');
	let params = $state<{ name: string; type: string; required: boolean; description: string; enumValues: string }[]>(
		action
			? Object.entries(action.params ?? {}).map(([name, p]) => ({
					name,
					type: p.type,
					required: p.required,
					description: p.description,
					enumValues: p.enum?.join(', ') ?? ''
				}))
			: []
	);

	let confirmingDelete = $state(false);

	const keyValid = $derived(/^[a-z][a-z0-9_]*$/.test(key));
	const canSave = $derived(key.length > 0 && keyValid && path.length > 0 && description.length > 0);

	function addParam() {
		params = [...params, { name: '', type: 'string', required: false, description: '', enumValues: '' }];
	}

	function removeParam(index: number) {
		params = params.filter((_, i) => i !== index);
	}

	function save() {
		const paramsObj: Record<string, ActionParam> = {};
		for (const p of params) {
			if (!p.name) continue;
			const param: ActionParam = {
				type: p.type,
				required: p.required,
				description: p.description
			};
			if (p.type === 'enum' && p.enumValues) {
				param.enum = p.enumValues.split(',').map((v) => v.trim()).filter(Boolean);
			}
			paramsObj[p.name] = param;
		}

		onsave(key, {
			method,
			path,
			description,
			risk,
			response_type: responseType || undefined,
			params: paramsObj
		});
	}
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="backdrop" onclick={oncancel}>
	<div
		class="modal"
		role="dialog"
		tabindex="-1"
		aria-modal="true"
		aria-labelledby="action-modal-title"
		onclick={(e) => e.stopPropagation()}
	>
		<header class="modal-head">
			<h2 id="action-modal-title">
				{isEdit ? `Edit Action: ${action?.key}` : 'New Action'}
			</h2>
			<button type="button" class="close-btn" onclick={oncancel} aria-label="Close">&#x2715;</button>
		</header>

		<div class="modal-body">
			<div class="row-2col">
				<label class="field">
					<span class="label">Key</span>
					<input
						type="text"
						bind:value={key}
						placeholder="send_message"
						disabled={readOnly || isEdit}
						class="mono-input"
					/>
					{#if key.length > 0 && !keyValid}
						<span class="field-error">Lowercase letters, digits, underscores. Must start with a letter.</span>
					{/if}
				</label>
				<label class="field">
					<span class="label">HTTP Method</span>
					<select bind:value={method} disabled={readOnly}>
						{#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as m}
							<option value={m}>{m}</option>
						{/each}
					</select>
				</label>
			</div>

			<label class="field">
				<span class="label">Path template</span>
				<input
					type="text"
					bind:value={path}
					placeholder="/repos/:owner/:repo/issues"
					disabled={readOnly}
					class="mono-input"
				/>
			</label>

			<label class="field">
				<span class="label">Description</span>
				<textarea
					bind:value={description}
					placeholder="Create pull request on owner/repo"
					disabled={readOnly}
					rows="2"
				></textarea>
			</label>

			<div class="row-2col">
				<label class="field">
					<span class="label">Risk level</span>
					<select bind:value={risk} disabled={readOnly}>
						<option value="low">Low</option>
						<option value="medium">Medium</option>
						<option value="high">High</option>
						<option value="critical">Critical</option>
					</select>
				</label>
				<label class="field">
					<span class="label">Response type</span>
					<input
						type="text"
						bind:value={responseType}
						placeholder="json"
						disabled={readOnly}
					/>
				</label>
			</div>

			<div class="params-section">
				<div class="params-head">
					<span class="label">Parameters</span>
					{#if !readOnly}
						<button type="button" class="btn-ghost" onclick={addParam}>+ Add parameter</button>
					{/if}
				</div>
				{#if params.length > 0}
					<div class="params-table">
						<div class="params-header">
							<span>Name</span>
							<span>Type</span>
							<span>Req?</span>
							<span>Description</span>
							{#if !readOnly}<span></span>{/if}
						</div>
						{#each params as p, i}
							<div class="params-row">
								<input type="text" bind:value={p.name} placeholder="param_name" disabled={readOnly} class="mono-input" />
								<select bind:value={p.type} disabled={readOnly}>
									<option value="string">string</option>
									<option value="number">number</option>
									<option value="boolean">boolean</option>
									<option value="enum">enum</option>
									<option value="object">object</option>
								</select>
								<input type="checkbox" bind:checked={p.required} disabled={readOnly} />
								<input type="text" bind:value={p.description} placeholder="Description" disabled={readOnly} />
								{#if !readOnly}
									<button type="button" class="btn-icon" onclick={() => removeParam(i)} aria-label="Remove parameter">&#x2715;</button>
								{/if}
							</div>
							{#if p.type === 'enum'}
								<div class="enum-row">
									<input
										type="text"
										bind:value={p.enumValues}
										placeholder="value1, value2, value3"
										disabled={readOnly}
										class="mono-input"
									/>
								</div>
							{/if}
						{/each}
					</div>
				{:else}
					<p class="muted">No parameters defined.</p>
				{/if}
			</div>
		</div>

		<footer class="modal-foot">
			{#if isEdit && !readOnly && ondelete}
				{#if confirmingDelete}
					<span class="delete-confirm">
						Are you sure?
						<button type="button" class="btn danger-fill" onclick={() => ondelete?.(action!.key)}>Yes, delete</button>
						<button type="button" class="btn" onclick={() => (confirmingDelete = false)}>No</button>
					</span>
				{:else}
					<button type="button" class="btn danger" onclick={() => (confirmingDelete = true)}>Delete action</button>
				{/if}
			{/if}
			<div class="foot-right">
				<button type="button" class="btn" onclick={oncancel}>Cancel</button>
				{#if !readOnly}
					<button type="button" class="btn primary" onclick={save} disabled={!canSave}>
						{isEdit ? 'Save' : 'Create'}
					</button>
				{/if}
			</div>
		</footer>
	</div>
</div>

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		overflow-y: auto;
		padding: 2rem 1rem;
	}
	.modal {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		max-width: 640px;
		width: 100%;
		box-shadow: 0 20px 50px rgba(0, 0, 0, 0.25);
		display: flex;
		flex-direction: column;
		max-height: 90vh;
	}
	.modal-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 1.25rem 1.5rem;
		border-bottom: 1px solid var(--color-border);
	}
	.modal-head h2 {
		margin: 0;
		font-size: 1.05rem;
	}
	.close-btn {
		background: none;
		border: none;
		font-size: 1.2rem;
		cursor: pointer;
		color: var(--color-text-muted);
		padding: 0.25rem;
	}
	.close-btn:hover {
		color: var(--color-text);
	}
	.modal-body {
		padding: 1.5rem;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.modal-foot {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 1rem 1.5rem;
		border-top: 1px solid var(--color-border);
		gap: 0.5rem;
	}
	.foot-right {
		display: flex;
		gap: 0.5rem;
		margin-left: auto;
	}
	.row-2col {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	.field-error {
		font-size: 0.75rem;
		color: #b91c1c;
	}
	input[type='text'],
	textarea,
	select {
		padding: 0.5rem 0.7rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: inherit;
		font: inherit;
		font-size: 0.88rem;
	}
	textarea {
		resize: vertical;
	}
	.mono-input {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.params-section {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.params-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.btn-ghost {
		background: none;
		border: none;
		color: var(--color-primary, #6366f1);
		cursor: pointer;
		font: inherit;
		font-size: 0.82rem;
		font-weight: 500;
		padding: 0.25rem 0.5rem;
	}
	.btn-ghost:hover {
		text-decoration: underline;
	}
	.params-table {
		display: flex;
		flex-direction: column;
		gap: 0;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		overflow: hidden;
	}
	.params-header {
		display: grid;
		grid-template-columns: 2fr 1.2fr 0.5fr 3fr 0.4fr;
		gap: 0.5rem;
		padding: 0.45rem 0.6rem;
		background: var(--color-bg);
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
		font-weight: 600;
	}
	.params-row {
		display: grid;
		grid-template-columns: 2fr 1.2fr 0.5fr 3fr 0.4fr;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		align-items: center;
		border-top: 1px solid var(--color-border);
	}
	.params-row input[type='text'],
	.params-row select {
		padding: 0.3rem 0.5rem;
		font-size: 0.82rem;
	}
	.params-row input[type='checkbox'] {
		justify-self: center;
	}
	.enum-row {
		padding: 0 0.6rem 0.4rem 0.6rem;
		border-top: none;
	}
	.enum-row input {
		width: 100%;
	}
	.btn-icon {
		background: none;
		border: none;
		cursor: pointer;
		color: var(--color-text-muted);
		font-size: 0.9rem;
		padding: 0.2rem;
	}
	.btn-icon:hover {
		color: #b91c1c;
	}
	.btn {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
		font-size: 0.85rem;
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.btn.danger {
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	.btn.danger-fill {
		background: #dc2626;
		color: white;
		border-color: #dc2626;
	}
	.delete-confirm {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.85rem;
		color: var(--color-text-muted);
	}
	.muted {
		color: var(--color-text-muted);
		font-size: 0.85rem;
		margin: 0;
	}
</style>
