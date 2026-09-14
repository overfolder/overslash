<script lang="ts">
	import type { ServiceInstanceSummary, ConnectionSummary, Identity } from '$lib/types';
	import { credentialStatus } from '$lib/api/service-status';
	import { resolveOwner, qualifyName } from '$lib/ownerLabel';

	let {
		services,
		connections,
		identityById = new Map(),
		currentUserId,
		allowedDomains = [],
		value,
		onchange
	}: {
		services: ServiceInstanceSummary[];
		connections: ConnectionSummary[];
		/** Org identities, for naming the owner of someone else's service. Empty
		 *  by default so this renders standalone — options are then unqualified. */
		identityById?: Map<string, Identity>;
		currentUserId?: string;
		allowedDomains?: string[];
		value: string | null;
		onchange: (v: string) => void;
	} = $props();

	const connectionIds = $derived(new Set(connections.map((c) => c.id)));

	// With the admin "show all users" view on, several users can each own a
	// service called `gcal`. The dropdown has no owner column to fall back on,
	// so the owner goes into the option label itself: `ada / gcal`.
	function optionLabel(s: ServiceInstanceSummary): string {
		const owner = resolveOwner(s.owner_identity_id, identityById, currentUserId, allowedDomains);
		return qualifyName(s.name, owner);
	}

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
					<option value={s.id}>{optionLabel(s)}  ·  {s.template_key}</option>
				{/each}
			</optgroup>
		{/if}
		{#if other.length > 0}
			<optgroup label="Other">
				{#each other as s (s.id)}
					<option value={s.id}>{optionLabel(s)}  ·  {s.template_key}</option>
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
