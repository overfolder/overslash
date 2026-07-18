<script lang="ts">
	import type { InstanceConfigParam } from '$lib/types';

	let {
		params,
		config = $bindable<Record<string, string>>({}),
		idPrefix = 'svc-config'
	}: {
		params: InstanceConfigParam[];
		config: Record<string, string>;
		idPrefix?: string;
	} = $props();

	// Same init contract as ServiceCredentials: every key must hold a string
	// before the inputs render, or binding an undefined map slot is a Svelte
	// error. The init-time loop covers first render, the effect covers `params`
	// changing under a live map (switching templates in the wizard).
	// svelte-ignore state_referenced_locally
	for (const p of params) {
		if (config[p.name] === undefined) config[p.name] = '';
	}
	$effect(() => {
		for (const p of params) {
			if (config[p.name] === undefined) config[p.name] = '';
		}
	});
</script>

{#each params as p (p.name)}
	<div class="field">
		<label class="label" for="{idPrefix}-{p.name}">
			{p.name}
			{#if !p.required}<span class="cfg-badge">optional</span>{/if}
		</label>
		<input
			id="{idPrefix}-{p.name}"
			type="text"
			bind:value={config[p.name]}
			autocomplete="off"
			spellcheck="false"
		/>
		{#if p.description}
			<small>{p.description}</small>
		{/if}
	</div>
{/each}

<style>
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.label {
		font-size: 0.78rem;
		font-weight: 600;
		color: var(--color-text-muted);
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-family: var(--font-mono);
	}
	.cfg-badge {
		font-size: 9px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		font-weight: 600;
		font-family: var(--font-sans);
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		padding: 1px 5px;
	}
	input {
		padding: 0.5rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		background: var(--color-bg);
		color: var(--color-text);
		font-size: 0.85rem;
		font-family: var(--font-mono);
	}
	input:focus {
		outline: none;
		border-color: var(--color-primary);
	}
	small {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
</style>
