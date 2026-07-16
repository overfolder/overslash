<script lang="ts">
	import SecretNamePicker from '$lib/components/SecretNamePicker.svelte';
	import type { SecretSummary, ServiceAuth } from '$lib/types';

	type ApiKeyScheme = Extract<ServiceAuth, { type: 'api_key' }>;

	let {
		schemes,
		credentials = $bindable<Record<string, string>>({}),
		available,
		loading = false,
		singleLabel = 'API key secret name',
		idPrefix = 'svc-cred'
	}: {
		schemes: ApiKeyScheme[];
		credentials: Record<string, string>;
		available: SecretSummary[];
		loading?: boolean;
		/** Label used when the template declares exactly one credential slot. */
		singleLabel?: string;
		idPrefix?: string;
	} = $props();

	// One slot is unambiguous — keep the familiar generic label. Several slots
	// must be told apart by their securityScheme key ("gateway", "mailbox").
	const showSchemeLabels = $derived(schemes.length > 1);
	const vaultNames = $derived(new Set(available.map((s) => s.name)));

	// Every scheme key gets an entry so the pickers bind to real slots even
	// when the caller seeded nothing (e.g. the create page). Writes only when
	// missing, so it converges.
	$effect(() => {
		for (const s of schemes) {
			const k = s.scheme ?? '';
			if (k && credentials[k] === undefined) credentials[k] = '';
		}
	});
</script>

{#each schemes as s (s.scheme ?? s.default_secret_name)}
	{@const key = s.scheme ?? ''}
	{@const isOrg = s.secret_source === 'org'}
	{@const bound = (credentials[key] ?? '').trim().length > 0}
	<div class="field">
		<label class="label" for="{idPrefix}-{key}">
			{showSchemeLabels ? `${key} secret name` : singleLabel}
			{#if s.optional}<span class="cred-badge">optional</span>{/if}
		</label>
		<SecretNamePicker
			id="{idPrefix}-{key}"
			bind:value={credentials[key]}
			{available}
			{loading}
			placeholder={isOrg && s.default_secret_name ? s.default_secret_name : 'my-api-key'}
		/>
		{#if s.description}
			<small>{s.description}</small>
		{/if}
		{#if isOrg && !bound && s.default_secret_name}
			<!-- The vault list is scoped to what THIS user can see; the org-wide
			     default may still resolve at execution time from another owner's
			     secret. Word it softly and never block saving on it. -->
			<small>
				Blank uses the org-wide <code>{s.default_secret_name}</code>{#if !loading}{vaultNames.has(
						s.default_secret_name
					)
						? ' (found in your vault)'
						: s.optional
							? ' (not set anywhere you can see — this credential is skipped)'
							: ' (not visible in your vault)'}{/if}.
			</small>
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
	}
	.cred-badge {
		font-size: 9px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		font-weight: 600;
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		padding: 1px 5px;
	}
	small {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
	small code {
		font-family: var(--font-mono);
		font-size: 0.72rem;
		background: var(--color-primary-bg);
		padding: 1px 4px;
		border-radius: var(--radius-sm);
	}
</style>
