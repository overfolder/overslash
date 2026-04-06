<script lang="ts">
	import type { AuditFilters } from './types';

	let {
		filters,
		onchange
	}: { filters: AuditFilters; onchange: (next: AuditFilters) => void } = $props();

	let identityId = $state(filters.identity_id ?? '');
	let action = $state(filters.action ?? '');
	let resourceType = $state(filters.resource_type ?? '');
	let since = $state(toLocalInput(filters.since));
	let until = $state(toLocalInput(filters.until));

	const RESOURCE_TYPES = ['', 'action', 'approval', 'secret', 'connection', 'identity', 'permission'];

	function toLocalInput(iso: string | undefined): string {
		if (!iso) return '';
		const d = new Date(iso);
		if (isNaN(d.getTime())) return '';
		const pad = (n: number) => String(n).padStart(2, '0');
		return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
	}

	function fromLocalInput(s: string): string | undefined {
		if (!s) return undefined;
		const d = new Date(s);
		if (isNaN(d.getTime())) return undefined;
		return d.toISOString();
	}

	function emit() {
		onchange({
			identity_id: identityId.trim() || undefined,
			action: action.trim() || undefined,
			resource_type: resourceType || undefined,
			since: fromLocalInput(since),
			until: fromLocalInput(until)
		});
	}

	function preset(ms: number) {
		const now = new Date();
		const start = new Date(now.getTime() - ms);
		since = toLocalInput(start.toISOString());
		until = toLocalInput(now.toISOString());
		emit();
	}

	function clearAll() {
		identityId = '';
		action = '';
		resourceType = '';
		since = '';
		until = '';
		emit();
	}
</script>

<div class="filters">
	<div class="row">
		<label>
			<span>Identity ID</span>
			<input type="text" bind:value={identityId} onchange={emit} placeholder="UUID" />
		</label>
		<label>
			<span>Event / Action</span>
			<input type="text" bind:value={action} onchange={emit} placeholder="e.g. action.executed" />
		</label>
		<label>
			<span>Resource type</span>
			<select bind:value={resourceType} onchange={emit}>
				{#each RESOURCE_TYPES as t}
					<option value={t}>{t || 'any'}</option>
				{/each}
			</select>
		</label>
	</div>
	<div class="row">
		<label>
			<span>Since</span>
			<input type="datetime-local" bind:value={since} onchange={emit} />
		</label>
		<label>
			<span>Until</span>
			<input type="datetime-local" bind:value={until} onchange={emit} />
		</label>
		<div class="presets">
			<button type="button" onclick={() => preset(60 * 60 * 1000)}>Last hour</button>
			<button type="button" onclick={() => preset(24 * 60 * 60 * 1000)}>24h</button>
			<button type="button" onclick={() => preset(7 * 24 * 60 * 60 * 1000)}>7d</button>
			<button type="button" onclick={() => preset(30 * 24 * 60 * 60 * 1000)}>30d</button>
			<button type="button" class="clear" onclick={clearAll}>Clear</button>
		</div>
	</div>
</div>

<style>
	.filters {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-4);
		background: var(--color-bg-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md, 8px);
		margin-bottom: var(--space-4);
	}
	.row {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-3);
		align-items: flex-end;
	}
	label {
		display: flex;
		flex-direction: column;
		gap: 4px;
		flex: 1 1 180px;
		min-width: 160px;
	}
	label span {
		font-size: var(--text-label, 0.75rem);
		color: var(--color-text-muted);
	}
	input,
	select {
		padding: 6px 10px;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		background: var(--color-bg);
		color: var(--color-text);
		font: inherit;
	}
	.presets {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
	}
	.presets button {
		padding: 6px 10px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		border-radius: var(--radius-sm, 4px);
		cursor: pointer;
	}
	.presets button:hover {
		border-color: var(--color-primary);
	}
	.presets .clear {
		color: var(--color-text-muted);
	}
</style>
