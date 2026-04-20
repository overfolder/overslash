<script lang="ts">
	import type { ServiceInstanceSummary, ConnectionSummary } from '$lib/types';
	import { credentialStatus } from '$lib/api/service-status';

	let {
		services,
		connections,
		value,
		onchange
	}: {
		services: ServiceInstanceSummary[];
		connections: ConnectionSummary[];
		value: string | null;
		onchange: (v: string) => void;
	} = $props();

	const connectionIds = $derived(new Set(connections.map((c) => c.id)));

	const connected = $derived(
		services.filter(
			(s) => s.status === 'active' && credentialStatus(s, connectionIds) === 'connected'
		)
	);
	const other = $derived(
		services.filter(
			(s) => !(s.status === 'active' && credentialStatus(s, connectionIds) === 'connected')
		)
	);
</script>

<label class="wrap">
	<span class="label">Service</span>
	<select
		class="control"
		value={value ?? ''}
		onchange={(e) => onchange((e.currentTarget as HTMLSelectElement).value)}
	>
		<option value="" disabled>Select a service…</option>
		{#if connected.length > 0}
			<optgroup label="Connected">
				{#each connected as s (s.id)}
					<option value={s.name}>{s.name}  ·  {s.template_key}</option>
				{/each}
			</optgroup>
		{/if}
		{#if other.length > 0}
			<optgroup label="Other">
				{#each other as s (s.id)}
					<option value={s.name}>{s.name}  ·  {s.template_key}</option>
				{/each}
			</optgroup>
		{/if}
	</select>
</label>

<style>
	.wrap {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.label {
		font: var(--text-label);
		color: var(--color-text);
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
</style>
